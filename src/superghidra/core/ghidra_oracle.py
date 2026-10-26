#!/usr/bin/env python3
"""
ghidra_oracle.py
================
Dual-mode persistent TCP/JSON daemon (127.0.0.1:5073) and high-speed CLI client
for headless Ghidra / PyGhidra reverse engineering and binary analysis.

Modes:
  1. serve:  Boots OpenJDK 21 + PyGhidra once, loads project in read-only mode,
             warms up DecompInterface and FlatProgramAPI, and listens on TCP 5073.
  2. client: High-speed sub-millisecond CLI queries. Auto-spawns daemon if offline.

Supported Commands:
  - decompile <addr...>          : Decompiled C code with VA and runtime RVA (- 0x100000).
  - vtable <addr> [count=12]     : VTable slots, function names, and runtime hook RVAs.
  - disassemble <addr> [count=30]: Instruction disassembly, hex bytes, and operands.
  - refs <addr> [count=20]       : Incoming cross-references with caller function names.
  - adrp_add <symbol_or_addr>    : Fast PC-relative string & pointer references via page index.
  - opcodes <min> <max>          : Fast opcode enumeration for `mov w0, #imm; ret` dispatcher gates.
  - rva <addr>                   : Instant VA <-> RVA translation (<1 ms, zero JVM call).
  - rename <addr> <name>         : Sets function/symbol rename in JSON write-overlay table.
  - comment <addr> <text>        : Sets address comment in JSON write-overlay table.
  - overlay [list|clear]         : Inspects or clears active JSON write-overlay entries.
  - type <name_or_id>            : Queries off-heap struct/type layout and C declaration.
  - register_struct <name> <sz>  : Registers deduplicated struct in off-heap type store.
  - mode [eco|balanced|turbo|auto]: Dynamic Governor mode switch.
  - hibernate                    : Forces immediate decompiler process hibernation & RAM cleanup.
  - clear-cache                  : Clears persistent L2 SQLite query cache.
  - status                       : Reports daemon uptime, function count, and LRU cache hit rate.
  - stop                         : Cleanly shuts down the daemon.
"""

import os
import sys
import time
import json
import socket
import struct
import sqlite3
import contextlib
import logging
import re
import subprocess
import threading
import secrets
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple, Union, Iterable, Sequence
from collections import OrderedDict

# Import DependencyCacheDAG and SemanticDeltaLog
try:
    from dependency_cache_dag import DependencyCacheDAG, FunctionNode, InvalidationImpactReport
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dependency_cache_dag import DependencyCacheDAG, FunctionNode, InvalidationImpactReport

try:
    from semantic_delta_log import SemanticDeltaLog, DeltaEventType, SemanticEvent, CommentType
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from semantic_delta_log import SemanticDeltaLog, DeltaEventType, SemanticEvent, CommentType

# Import OffHeapTypeStore, OracleTypeStoreAdapter, TypeDeduplicator, TypeKind, StructMember
try:
    from dwarf_pdb_preindexer import (
        OffHeapTypeStore,
        OracleTypeStoreAdapter,
        TypeDeduplicator,
        TypeKind,
        StructMember,
    )
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dwarf_pdb_preindexer import (
        OffHeapTypeStore,
        OracleTypeStoreAdapter,
        TypeDeduplicator,
        TypeKind,
        StructMember,
    )

# Import Resource Governor components
try:
    from resource_governor import (
        ResourceMode,
        ModePolicy,
        get_default_mode_policy,
        DecompilerComplexityGovernor,
        FunctionComplexityTier,
    )
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from resource_governor import (
        ResourceMode,
        ModePolicy,
        get_default_mode_policy,
        DecompilerComplexityGovernor,
        FunctionComplexityTier,
    )
# ==============================================================================
# Configuration & Constants
# ==============================================================================

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5073
DEFAULT_IMAGE_BASE = 0x100000  # Default ELF image base offset (- 0x100000)
DAEMON_STARTUP_TIMEOUT = 40.0   # Maximum seconds to wait for daemon JVM warmup
OVERLAY_FILENAME = "ghidra_overlay.json"
DAEMON_LOG_FILENAME = "ghidra_oracle_daemon.log"
L2_CACHE_FILENAME = "ghidra_oracle_cache.db"
DEFAULT_TOKEN_FILENAME = "daemon.token"
MAX_REQUEST_SIZE = 2 * 1024 * 1024  # 2 MB limit per request payload
SUPERGHIDRA_DATA_DIR_ENV = "SUPERGHIDRA_DATA_DIR"
SUPERGHIDRA_TOKEN_ENV = "SUPERGHIDRA_SESSION_TOKEN"

MUTATING_COMMANDS = {
    "stop",
    "rename",
    "comment",
    "clear",
    "clear-cache",
    "register_struct",
    "mode",
    "hibernate",
}

READ_ONLY_COMMANDS = {
    "ping",
    "status",
    "rva",
    "decompile",
    "vtable",
    "disassemble",
    "refs",
    "references",
    "adrp_add",
    "opcodes",
    "type",
    "overlay",
}


def is_loopback_host(host: str) -> bool:
    """Checks whether the specified host address is a local loopback interface."""
    if not host or not isinstance(host, str):
        return False
    h = host.strip().strip("[]").lower()
    if h in ("localhost", "ip6-localhost", "ipv6-localhost"):
        return True
    if h.startswith("127."):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback
    except ValueError:
        return False


def get_default_token_path() -> str:
    """Returns the persistent file path where daemon.token is stored."""
    data_dir = os.environ.get(SUPERGHIDRA_DATA_DIR_ENV)
    if data_dir:
        dir_path = os.path.abspath(data_dir)
    else:
        dir_path = os.path.join(os.path.expanduser("~"), ".superghidra")
    return os.path.join(dir_path, DEFAULT_TOKEN_FILENAME)


def save_session_token(token: str, path: Optional[str] = None) -> str:
    """Saves session token to disk with restricted permissions (0o600)."""
    token_path = path or get_default_token_path()
    os.makedirs(os.path.dirname(token_path), exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    try:
        fd = os.open(token_path, flags, mode)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(token.strip())
        if hasattr(os, "chmod"):
            try:
                os.chmod(token_path, 0o600)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Could not save daemon token to {token_path}: {e}")
    return token_path


def load_session_token(token_arg: Optional[str] = None, token_path: Optional[str] = None) -> Optional[str]:
    """Resolves session token from argument, environment variable, or token file on disk."""
    if token_arg:
        return token_arg.strip()
    env_token = os.environ.get(SUPERGHIDRA_TOKEN_ENV)
    if env_token:
        return env_token.strip()
    path = token_path or get_default_token_path()
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            logger.debug(f"Could not read daemon token file {path}: {e}")
    return None

# No built-in projects: pass --project-dir/--project-name, or set
# SUPERGHIDRA_PROJECTS to "dir,name[,program]" entries separated by ";".
DEFAULT_PROJECT_CANDIDATES: List[Tuple[str, str, Optional[str]]] = []
PROJECT_CANDIDATES = list(DEFAULT_PROJECT_CANDIDATES)


def get_project_candidates() -> List[Tuple[str, str, Optional[str]]]:
    """Returns candidate project tuples from the SUPERGHIDRA_PROJECTS env var."""
    env_projects = os.environ.get("SUPERGHIDRA_PROJECTS")
    candidates: List[Tuple[str, str, Optional[str]]] = []
    if env_projects:
        for item in env_projects.split(";"):
            item = item.strip()
            if not item:
                continue
            parts = [p.strip() for p in item.split(",")]
            if len(parts) >= 3:
                candidates.append((parts[0], parts[1], parts[2]))
            elif len(parts) == 2:
                candidates.append((parts[0], parts[1], None))
            elif len(parts) == 1:
                p_path = parts[0]
                candidates.append((os.path.dirname(p_path) or ".", os.path.basename(p_path), None))
    candidates.extend(DEFAULT_PROJECT_CANDIDATES)
    return candidates


logger = logging.getLogger("ghidra_oracle")


# ==============================================================================
# Environment Configuration
# ==============================================================================

def setup_environment(ghidra_dir: Optional[str] = None, java_home: Optional[str] = None):
    """Configures JDK 21 and Ghidra environment paths before starting PyGhidra."""
    g_dir = ghidra_dir or os.environ.get("GHIDRA_INSTALL_DIR")
    if g_dir:
        os.environ["GHIDRA_INSTALL_DIR"] = g_dir

    j_home = java_home or os.environ.get("JAVA_HOME")
    if j_home:
        os.environ["JAVA_HOME"] = j_home
        java_bin = os.path.join(j_home, "bin")
        cur_path = os.environ.get("PATH", "")
        if java_bin not in cur_path.split(os.pathsep):
            os.environ["PATH"] = java_bin + os.pathsep + cur_path


# ==============================================================================
# Address Parsing & VA <-> RVA Arithmetic (Zero JVM call, <1ms)
# ==============================================================================

def parse_addr_int(addr_input: Any) -> int:
    """Parses hex or decimal address representations to integer."""
    if isinstance(addr_input, int):
        return addr_input
    s = str(addr_input).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 16) if any(c in "abcdefABCDEF" for c in s) else int(s)
    except ValueError:
        return int(s, 16)


def normalize_hex_key(addr_input: Any) -> str:
    """Returns canonical '0x00123456' format string for address keys, or string symbol if non-address."""
    try:
        val = parse_addr_int(addr_input)
        return f"0x{val:08X}"
    except (ValueError, TypeError):
        return str(addr_input).strip()



def va_to_rva(va: int, base: int = DEFAULT_IMAGE_BASE) -> int:
    """Translates Ghidra VA to runtime RVA."""
    return va - base if va >= base else va


def rva_to_va(rva: int, base: int = DEFAULT_IMAGE_BASE) -> int:
    """Translates runtime RVA to Ghidra VA."""
    return rva + base


def normalize_address_pair(addr_input: Any, base: int = DEFAULT_IMAGE_BASE) -> Tuple[int, int]:
    """Returns (va, rva) pair from either VA or RVA input."""
    val = parse_addr_int(addr_input)
    if val >= base:
        va = val
        rva = val - base
    else:
        rva = val
        va = val + base
    return va, rva


# ==============================================================================
# LRU Cache
# ==============================================================================

class LRUCache:
    """Thread-safe LRU Cache with hit/miss metric tracking."""

    def __init__(self, capacity: int = 512):
        self.capacity = capacity
        self.cache: OrderedDict = OrderedDict()
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            if key in self.cache:
                self.hits += 1
                self.cache.move_to_end(key)
                return self.cache[key]
            # Fallback for single key lookup when cache has tuple keys (e.g. (va, style))
            if not isinstance(key, tuple):
                for k, v in self.cache.items():
                    if isinstance(k, tuple) and len(k) > 0 and (k[0] == key or str(k[0]) == str(key)):
                        self.hits += 1
                        return v
            self.misses += 1
            return None

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            rate = (self.hits / total * 100.0) if total > 0 else 0.0
            return {
                "size": len(self.cache),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_pct": round(rate, 2),
            }

    def evict(self, key: Any) -> bool:
        with self._lock:
            found = False
            if key in self.cache:
                del self.cache[key]
                found = True
            # Also evict tuple keys where first element matches
            matching = [k for k in list(self.cache.keys()) if isinstance(k, tuple) and len(k) > 0 and (k[0] == key or str(k[0]) == str(key))]
            for k in matching:
                del self.cache[k]
                found = True
            return found

    def evict_batch(self, keys: Iterable[Any]) -> List[Any]:
        evicted = []
        with self._lock:
            for k in keys:
                if k in self.cache:
                    del self.cache[k]
                    evicted.append(k)
                matching = [mk for mk in list(self.cache.keys()) if isinstance(mk, tuple) and len(mk) > 0 and (mk[0] == k or str(mk[0]) == str(k))]
                for mk in matching:
                    del self.cache[mk]
                    evicted.append(mk)
        return evicted

    def clear(self) -> None:
        with self._lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0



# ==============================================================================
# Persistent L2 SQLite Cache (0% JVM CPU on repeats)
# ==============================================================================

class L2SQLiteCache:
    """
    Persistent WAL-mode SQLite cache for sub-millisecond local responses.
    Caches decompile, vtable, disassemble, refs, adrp_add, and opcodes queries.
    Enables instant lookups with 0% JVM CPU even when the daemon is offline.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            cache_dir = os.path.join(os.path.expanduser("~"), ".cache")
            os.makedirs(cache_dir, exist_ok=True)
            db_path = os.path.join(cache_dir, L2_CACHE_FILENAME)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @contextlib.contextmanager
    def _conn_ctx(self):
        conn = self._get_conn()
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _init_db(self) -> None:
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS oracle_cache (
                            query_type TEXT NOT NULL,
                            query_key TEXT NOT NULL,
                            program_id TEXT NOT NULL DEFAULT '',
                            data_json TEXT NOT NULL,
                            timestamp REAL NOT NULL,
                            PRIMARY KEY (query_type, query_key, program_id)
                        )
                    """)
                    cols = [r[1] for r in conn.execute("PRAGMA table_info(oracle_cache)").fetchall()]
                    if "program_id" not in cols:
                        conn.execute("ALTER TABLE oracle_cache ADD COLUMN program_id TEXT NOT NULL DEFAULT ''")
                    # Purge any un-scoped legacy rows written before program scoping
                    conn.execute("DELETE FROM oracle_cache WHERE program_id = ''")
                    conn.commit()
            except Exception as e:
                logger.warning(f"Failed to initialize L2 SQLite cache at {self.db_path}: {e}")

    def get(self, query_type: str, query_key: str, program_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    if program_id:
                        cur = conn.execute(
                            """
                            SELECT data_json, timestamp FROM oracle_cache
                            WHERE query_type = ? AND query_key = ? AND program_id = ?
                            LIMIT 1
                            """,
                            (query_type, str(query_key).lower(), str(program_id))
                        )
                    else:
                        cur = conn.execute(
                            "SELECT data_json, timestamp FROM oracle_cache WHERE query_type = ? AND query_key = ? LIMIT 1",
                            (query_type, str(query_key).lower())
                        )
                    row = cur.fetchone()
                    if row:
                        data = json.loads(row[0])
                        data["l2_cached"] = True
                        data["l2_timestamp"] = float(row[1])
                        return data
            except Exception as e:
                logger.debug(f"L2 cache read error: {e}")
        return None

    def put(
        self,
        query_type: str,
        query_key: str,
        data: Dict[str, Any],
        timestamp: Optional[float] = None,
        program_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            try:
                data_copy = dict(data)
                data_copy.pop("l2_cached", None)
                data_copy.pop("cached", None)
                data_copy.pop("l2_timestamp", None)
                ts = timestamp if timestamp is not None else time.time()
                prog_id = str(program_id or "")
                with self._conn_ctx() as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO oracle_cache (query_type, query_key, program_id, data_json, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (query_type, str(query_key).lower(), prog_id, json.dumps(data_copy), ts))
                    conn.commit()
            except Exception as e:
                logger.debug(f"L2 cache write error: {e}")

    def evict(
        self,
        query_type: Optional[str] = None,
        query_key: Optional[str] = None,
        older_than_sec: Optional[float] = None,
        max_entries: Optional[int] = None,
    ) -> int:
        """
        Evicts cached entries by type, key, age, or capacity limit.
        Returns the number of rows removed.
        """
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    # Capacity-based eviction
                    if max_entries is not None and max_entries >= 0:
                        cur = conn.execute("SELECT COUNT(*) FROM oracle_cache")
                        count = cur.fetchone()[0]
                        if count > max_entries:
                            excess = count - max_entries
                            cur = conn.execute(
                                """
                                DELETE FROM oracle_cache
                                WHERE rowid IN (
                                    SELECT rowid FROM oracle_cache
                                    ORDER BY timestamp ASC
                                    LIMIT ?
                                )
                                """,
                                (excess,),
                            )
                            conn.commit()
                            return cur.rowcount
                        return 0

                    conditions = []
                    params: List[Any] = []
                    if query_type is not None:
                        conditions.append("query_type = ?")
                        params.append(query_type)
                    if query_key is not None:
                        conditions.append("query_key = ?")
                        params.append(str(query_key).lower())
                    if older_than_sec is not None:
                        cutoff = time.time() - older_than_sec
                        conditions.append("timestamp < ?")
                        params.append(cutoff)

                    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
                    cur = conn.execute(f"DELETE FROM oracle_cache {where_clause}", params)
                    conn.commit()
                    return cur.rowcount
            except Exception as e:
                logger.warning(f"L2 cache eviction error: {e}")
                return 0

    def clear(self) -> int:
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute("DELETE FROM oracle_cache")
                    deleted = cur.rowcount
                    conn.commit()
                    return deleted
            except Exception as e:
                logger.warning(f"L2 cache clear error: {e}")
                return 0

    def count(self) -> int:
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute("SELECT COUNT(*) FROM oracle_cache")
                    row = cur.fetchone()
                    return row[0] if row else 0
            except Exception as e:
                logger.debug(f"L2 cache count error: {e}")
                return 0

    def invalidate_address(self, va: Any, program_id: Optional[str] = None) -> int:
        """
        Deletes cached entries from L2 SQLite cache matching the given virtual address
        across all query types that may embed names (decompile, vtable, refs, disassemble).
        Matches both direct address keys and JSON target arrays. Returns deleted rowcount.
        """
        with self._lock:
            try:
                candidates = set()
                try:
                    v_int = parse_addr_int(va)
                    candidates.add(f"0x{v_int:08x}".lower())
                    candidates.add(hex(v_int).lower())
                    candidates.add(f"{v_int:x}".lower())
                    candidates.add(str(v_int))
                except Exception:
                    pass
                if isinstance(va, str):
                    candidates.add(va.strip().lower())

                with self._conn_ctx() as conn:
                    select_sql = """
                        SELECT query_type, query_key FROM oracle_cache
                        WHERE query_type IN ('decompile', 'vtable', 'refs', 'references', 'disassemble')
                    """
                    params: List[Any] = []
                    if program_id:
                        select_sql += " AND program_id = ?"
                        params.append(str(program_id))

                    cur = conn.execute(select_sql, params)
                    items_to_delete = []
                    for row in cur.fetchall():
                        qtype, qkey = row[0], row[1]
                        qkey_lower = qkey.lower()
                        # Direct match
                        if qkey_lower in candidates:
                            items_to_delete.append((qtype, qkey))
                            continue
                        # Target array or substring match in JSON
                        for cand in candidates:
                            if f'"{cand}"' in qkey_lower or f"'{cand}'" in qkey_lower or f": {cand}" in qkey_lower:
                                items_to_delete.append((qtype, qkey))
                                break
                    deleted = 0
                    for qt, k in items_to_delete:
                        del_sql = "DELETE FROM oracle_cache WHERE query_type = ? AND query_key = ?"
                        del_params = [qt, k]
                        if program_id:
                            del_sql += " AND program_id = ?"
                            del_params.append(str(program_id))
                        c = conn.execute(del_sql, del_params)
                        deleted += c.rowcount
                    conn.commit()
                    return deleted
            except Exception as e:
                logger.warning(f"L2 cache invalidate_address error for {va}: {e}")
                return 0

    def invalidate_program(self, program_id: str) -> int:
        """Deletes all cached rows for a specific program identity."""
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute("DELETE FROM oracle_cache WHERE program_id = ?", (str(program_id),))
                    deleted = cur.rowcount
                    conn.commit()
                    return deleted
            except Exception as e:
                logger.warning(f"L2 cache invalidate_program error for {program_id}: {e}")
                return 0

    def close(self) -> None:
        """Closes any persistent resources."""
        pass



# ==============================================================================
# In-Memory + JSON Write-Overlay Table
# ==============================================================================

class WriteOverlay:
    """
    Maintains an in-memory and persistent JSON overlay table for symbol renames
    and address comments without modifying the read-only Ghidra project database.
    """

    def __init__(self, filepath: Optional[str] = None):
        if filepath is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(base_dir, OVERLAY_FILENAME)
        self.filepath = filepath
        self._lock = threading.Lock()
        self.renames: Dict[str, str] = {}
        self.comments: Dict[str, str] = {}
        self.prototypes: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            if os.path.exists(self.filepath):
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.renames = {normalize_hex_key(k): v for k, v in data.get("renames", {}).items()}
                        self.comments = {normalize_hex_key(k): v for k, v in data.get("comments", {}).items()}
                        self.prototypes = {normalize_hex_key(k): v for k, v in data.get("prototypes", {}).items()}
                except Exception as e:
                    logger.warning(f"Failed to load write-overlay from {self.filepath}: {e}")

    def save(self) -> None:
        with self._lock:
            try:
                temp_file = self.filepath + ".tmp"
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "renames": self.renames,
                            "comments": self.comments,
                            "prototypes": self.prototypes,
                        },
                        f,
                        indent=2,
                    )
                if os.path.exists(self.filepath):
                    os.replace(temp_file, self.filepath)
                else:
                    os.rename(temp_file, self.filepath)
            except Exception as e:
                logger.error(f"Failed to save write-overlay to {self.filepath}: {e}")

    def set_rename(self, addr_input: Any, name: str) -> None:
        key = normalize_hex_key(addr_input)
        with self._lock:
            self.renames[key] = name
        self.save()

    def set_comment(self, addr_input: Any, comment: str) -> None:
        key = normalize_hex_key(addr_input)
        with self._lock:
            self.comments[key] = comment
        self.save()

    def get_rename(self, va: int, rva: int) -> Optional[str]:
        with self._lock:
            for k in [normalize_hex_key(va), normalize_hex_key(rva)]:
                if k in self.renames:
                    return self.renames[k]
        return None

    def set_prototype(self, addr_input: Any, prototype_text: str) -> None:
        """Record an IDA-style prototype binding. Never writes a Ghidra ``.rep``."""
        key = normalize_hex_key(addr_input)
        with self._lock:
            self.prototypes[key] = prototype_text
        self.save()

    def get_prototype(self, va: int, rva: Optional[int] = None) -> Optional[str]:
        with self._lock:
            keys = [normalize_hex_key(va)]
            if rva is not None:
                keys.append(normalize_hex_key(rva))
            for k in keys:
                if k in self.prototypes:
                    return self.prototypes[k]
        return None

    def get_comment(self, va: int, rva: int) -> Optional[str]:
        with self._lock:
            for k in [normalize_hex_key(va), normalize_hex_key(rva)]:
                if k in self.comments:
                    return self.comments[k]
        return None

    def apply_to_c_code(self, c_code: str, image_base: int = DEFAULT_IMAGE_BASE) -> str:
        """
        Replaces occurrences of FUN_<va_hex> or FUN_<rva_hex> (case-insensitive 8-hex-digit addresses)
        and any known renamed symbols in self.renames inside decompiled C source code.
        """
        if not c_code:
            return c_code

        with self._lock:
            if not self.renames:
                return c_code
            renames_copy = dict(self.renames)

        def _replace_fun(match: re.Match) -> str:
            hex_str = match.group(1)
            try:
                val = int(hex_str, 16)
            except ValueError:
                return match.group(0)

            # Check direct VA, RVA, and image base translation
            candidates = [val]
            if val >= image_base:
                candidates.append(val - image_base)
            else:
                candidates.append(val + image_base)

            for cand in candidates:
                k = normalize_hex_key(cand)
                if k in renames_copy:
                    return renames_copy[k]

            return match.group(0)

        # Replace FUN_<8hex> (case-insensitive)
        result = re.sub(r"\bFUN_([0-9a-fA-F]{8})\b", _replace_fun, c_code, flags=re.IGNORECASE)

        # Also replace any non-address symbol names in renames_copy if present
        for old_sym, new_sym in renames_copy.items():
            if not old_sym.lower().startswith("0x"):
                pattern = r"\b" + re.escape(old_sym) + r"\b"
                result = re.sub(pattern, new_sym, result)

        return result

    def clear(self) -> None:
        with self._lock:
            self.renames.clear()
            self.comments.clear()
            self.prototypes.clear()
        self.save()


    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "renames": dict(self.renames),
                "comments": dict(self.comments),
                "file": self.filepath,
            }


# ==============================================================================
# Ghidra Oracle Session (Headless PyGhidra Core)
# ==============================================================================

class GhidraOracleSession:
    """Manages the single loaded Ghidra project in read-only mode."""

    def __init__(
        self,
        project_dir: Optional[str] = None,
        project_name: Optional[str] = None,
        program_name: Optional[str] = None,
        resource_mode: str = "balanced",
        l2_cache: Optional[L2SQLiteCache] = None,
        overlay: Optional[WriteOverlay] = None,
        clean_stale_locks: bool = False,
        lock_stale_threshold_sec: float = 600.0,
    ):
        self.project_dir = project_dir
        self.project_name = project_name
        self.program_name = program_name
        self.clean_stale_locks = clean_stale_locks
        self.lock_stale_threshold_sec = lock_stale_threshold_sec

        self.project = None
        self.program = None
        self.flat_api = None
        self.decompiler = None
        self.monitor = None
        self.image_base = DEFAULT_IMAGE_BASE

        self.start_time = time.time()
        self.decompile_cache = LRUCache(512)
        self.vtable_cache = LRUCache(512)
        self.overlay = overlay if overlay is not None else WriteOverlay()
        self.l2_cache = l2_cache if l2_cache is not None else L2SQLiteCache()
        self.dep_dag = DependencyCacheDAG()
        delta_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ghidra-delta.jsonl")
        self.delta_log = SemanticDeltaLog(delta_log_path)
        self.type_store = OffHeapTypeStore()
        self.type_adapter = OracleTypeStoreAdapter(self.type_store)


        # Section 8 Resource Governor & Decompiler Watchdog state
        self.resource_mode = "balanced"  # eco, balanced, turbo, auto
        self.idle_timeout_sec = 120.0
        self.throttle_ms = 10
        self.last_decompile_time = time.time()
        self.is_hibernating = False
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_stop = threading.Event()
        self._session_lock = threading.Lock()
        self._engine_lock = threading.RLock()

        if resource_mode and resource_mode != "balanced":
            self.set_resource_mode(resource_mode)

        # Pre-indexed opcode gates: list of (imm, va, rva)
        self._opcode_gates: List[Tuple[int, int, int]] = []
        # Pre-indexed ADRP pages: dict mapping page_va -> list of (insn_va, dest_reg, paired_insn_info)
        self._adrp_pages: Dict[int, List[Dict[str, Any]]] = {}

    def get_program_id(self) -> str:
        """Returns deterministic program identity string."""
        if hasattr(self, "program") and self.program:
            prog_name = getattr(self, "program_name", "") or ""
            img_base = getattr(self, "image_base", 0) or 0
            return f"{prog_name}:{img_base:#x}"
        if self.project_name or self.program_name:
            return f"{self.project_name or ''}:{self.program_name or ''}"
        return ""

    @property
    def program_id(self) -> str:
        return self.get_program_id()

    def clean_locks(
        self,
        proj_dir: str,
        proj_name: str,
        clean_stale_locks: Optional[bool] = None,
        stale_threshold_sec: Optional[float] = None,
    ) -> List[str]:
        """
        Safely inspects Ghidra project lock files.
        By default, does NOT delete anything and logs a warning listing locks found.
        Only deletes if opt-in is enabled (clean_stale_locks=True), file mtime is
        older than threshold (default 10 min), and on POSIX non-blocking flock succeeds.
        Returns list of deleted file paths.
        """
        opt_in = self.clean_stale_locks if clean_stale_locks is None else clean_stale_locks
        threshold = self.lock_stale_threshold_sec if stale_threshold_sec is None else stale_threshold_sec

        deleted = []
        for lock_name in [f"{proj_name}.lock", f"{proj_name}.lock~"]:
            p = os.path.join(proj_dir, lock_name)
            if not os.path.exists(p):
                continue

            try:
                mtime = os.path.getmtime(p)
                age_sec = time.time() - mtime
            except OSError as e:
                logger.warning(f"Could not inspect lock file '{p}': {e}")
                continue

            if not opt_in:
                logger.warning(
                    f"Found existing Ghidra lock file '{p}' (age: {age_sec:.1f}s). Skipping removal (clean_stale_locks opt-in not set)."
                )
                continue

            if age_sec < threshold:
                logger.warning(
                    f"Lock file '{p}' is active or recent (age: {age_sec:.1f}s < threshold {threshold:.1f}s), skipping removal."
                )
                continue

            # On POSIX, verify flock non-blocking lock can be acquired
            if os.name != "nt":
                try:
                    import fcntl
                    with open(p, "r+") as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except (IOError, OSError) as e:
                    logger.warning(f"Lock file '{p}' is held by an active process, skipping removal: {e}")
                    continue

            try:
                os.remove(p)
                deleted.append(p)
                logger.info(f"Removed stale lock file '{p}' (age: {age_sec:.1f}s)")
            except OSError as e:
                logger.warning(f"Failed to remove stale lock file '{p}': {e}")

        return deleted

    def initialize(self) -> None:
        """Boots PyGhidra and opens the project in read-only mode."""
        setup_environment()
        import pyghidra
        pyghidra.start(False)

        from ghidra.base.project import GhidraProject
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        if self.project_dir and self.project_name:
            candidates = [(self.project_dir, self.project_name, self.program_name)]
            is_explicit = True
        else:
            candidates = list(get_project_candidates())
            is_explicit = False

        opened = False
        last_err = None
        for p_dir, p_name, prg_name in candidates:
            if not os.path.exists(p_dir):
                continue
            self.clean_locks(p_dir, p_name)
            try:
                # restoreProject=False prevents lock collisions and overhead
                proj = GhidraProject.openProject(p_dir, p_name, False)
                prog = None
                if prg_name:
                    try:
                        prog = proj.openProgram("/", prg_name, True)
                    except Exception as e:
                        last_err = e
                if prog is None:
                    # Pick first program from root folder
                    files = proj.getRootFolder().getFiles()
                    if files:
                        prog = proj.openProgram("/", files[0].getName(), True)

                if prog is not None:
                    self.project = proj
                    self.program = prog
                    self.project_dir = p_dir
                    self.project_name = p_name
                    self.program_name = prog.getName()
                    self.image_base = prog.getImageBase().getOffset()
                    opened = True
                    logger.info(
                        f"Loaded Ghidra program '{self.program_name}' from project '{p_name}' at {p_dir}"
                    )
                    break
                else:
                    proj.close()
            except Exception as e:
                last_err = e
                continue

        if not opened:
            if is_explicit:
                raise RuntimeError(
                    f"Failed to open requested Ghidra project '{self.project_name}' in '{self.project_dir}': {last_err}"
                )
            if not candidates:
                raise RuntimeError(
                    "No Ghidra project configured. Pass --project-dir and --project-name, "
                    "or set SUPERGHIDRA_PROJECTS=\"<dir>,<name>[,<program>]\"."
                )
            raise RuntimeError(
                f"Could not open any Ghidra project candidates in read-only mode! Last error: {last_err}"
            )

        self.flat_api = FlatProgramAPI(self.program)
        self.monitor = ConsoleTaskMonitor()

        # Warm up decompiler
        self.decompiler = DecompInterface()
        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.openProgram(self.program)

        # Warm up & build fast indexes (opcodes & ADRP pages)
        self._build_fast_indexes()

        # Start native decompiler idle reaper watchdog (Section 8.2)
        self._start_decompiler_watchdog()

    def _start_decompiler_watchdog(self) -> None:
        """Starts watchdog thread monitoring native decompiler idle timeout."""
        if self._watchdog_thread is None or not self._watchdog_thread.is_alive():
            self._watchdog_stop.clear()
            self._watchdog_thread = threading.Thread(
                target=self._decompiler_watchdog_loop,
                name="DecompilerReaperWatchdog",
                daemon=True,
            )
            self._watchdog_thread.start()

    def _decompiler_watchdog_loop(self) -> None:
        """Polls every 3 seconds to reap idle native decompile.exe subprocesses."""
        while not self._watchdog_stop.wait(3.0):
            if self.idle_timeout_sec <= 0:
                continue  # Turbo mode: permanently warm
            idle_duration = time.time() - self.last_decompile_time
            if not self.is_hibernating and idle_duration >= self.idle_timeout_sec:
                logger.info(
                    f"Decompiler idle for {idle_duration:.1f}s >= {self.idle_timeout_sec}s. Hibernating native process..."
                )
                self.hibernate()

    def hibernate(self) -> Dict[str, Any]:
        """
        Forces immediate native decompiler hibernation & RAM release (Section 8.2).
        Calls decompiler.flushCache(), decompiler.stopProcess(), and triggers System.gc().
        """
        with self._engine_lock:
            with self._session_lock:
                if self.decompiler is not None:
                    try:
                        self.decompiler.flushCache()
                        self.decompiler.stopProcess()
                    except Exception as e:
                        logger.debug(f"decompiler.stopProcess() notice: {e}")
                self.is_hibernating = True

                # Trigger JVM garbage collection to release unused pages
                try:
                    import java.lang.System
                    java.lang.System.gc()
                except Exception:
                    pass

                return {
                    "status": "ok",
                    "message": "Native decompiler process hibernated; idle RAM reclaimed via System.gc()",
                    "is_hibernating": True,
                }

    def _ensure_decompiler_active(self) -> None:
        """Re-arms the native decompiler process if currently hibernated."""
        self.last_decompile_time = time.time()
        if self.is_hibernating or self.decompiler is None:
            with self._engine_lock:
                with self._session_lock:
                    if self.decompiler is None:
                        from ghidra.app.decompiler import DecompInterface, DecompileOptions
                        self.decompiler = DecompInterface()
                        options = DecompileOptions()
                        self.decompiler.setOptions(options)
                    if self.program is not None:
                        self.decompiler.openProgram(self.program)
                    self.is_hibernating = False
                logger.info("Native decompiler process re-armed and program opened.")

    def set_resource_mode(self, mode: str) -> Dict[str, Any]:
        """
        Hot-swaps running daemon between eco, balanced, turbo, and auto resource profiles.
        """
        with self._engine_lock:
            mode_lower = mode.lower().strip()
            if mode_lower == "eco":
                self.resource_mode = "eco"
                self.idle_timeout_sec = 15.0
                self.throttle_ms = 50
                self.decompile_cache.capacity = 128
                self.vtable_cache.capacity = 128
                try:
                    import psutil
                    p = psutil.Process()
                    p.cpu_affinity([0])
                    p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 15)
                except Exception:
                    pass
            elif mode_lower == "balanced":
                self.resource_mode = "balanced"
                self.idle_timeout_sec = 120.0
                self.throttle_ms = 10
                self.decompile_cache.capacity = 512
                self.vtable_cache.capacity = 512
                try:
                    import psutil
                    p = psutil.Process()
                    avail = list(range(min(2, os.cpu_count() or 2)))
                    p.cpu_affinity(avail)
                    p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 5)
                except Exception:
                    pass
            elif mode_lower == "turbo":
                self.resource_mode = "turbo"
                self.idle_timeout_sec = 0.0  # Never hibernate
                self.throttle_ms = 0
                self.decompile_cache.capacity = 2048
                self.vtable_cache.capacity = 2048
                try:
                    import psutil
                    p = psutil.Process()
                    p.cpu_affinity(list(range(os.cpu_count() or 8)))
                    p.nice(psutil.NORMAL_PRIORITY_CLASS if os.name == "nt" else 0)
                except Exception:
                    pass
            elif mode_lower == "auto":
                self.resource_mode = "auto"
                self.idle_timeout_sec = 60.0
                self.throttle_ms = 10
                self.decompile_cache.capacity = 1024
                self.vtable_cache.capacity = 1024
                try:
                    import psutil
                    p = psutil.Process()
                    avail = list(range(min(4, os.cpu_count() or 4)))
                    p.cpu_affinity(avail)
                    p.nice(psutil.NORMAL_PRIORITY_CLASS if os.name == "nt" else 0)
                except Exception:
                    pass
            else:
                return {
                    "status": "error",
                    "message": f"Unknown mode '{mode}'. Choose from: eco, balanced, turbo, auto",
                }

            return {
                "status": "ok",
                "mode": self.resource_mode,
            "idle_timeout_sec": self.idle_timeout_sec,
            "throttle_ms": self.throttle_ms,
            "cache_capacity": self.decompile_cache.capacity,
            "message": f"Daemon resource mode updated to '{self.resource_mode}'",
        }

    def close(self) -> None:
        """Cleanly releases program and closes the project."""
        self._watchdog_stop.set()
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=1.0)

        if self.decompiler is not None:
            try:
                self.decompiler.dispose()
            except Exception:
                pass
            self.decompiler = None

        if self.project is not None and self.program is not None:
            try:
                self.project.close(self.program)
            except Exception:
                pass
            self.program = None

        if self.project is not None:
            try:
                self.project.close()
            except Exception:
                pass
            self.project = None

    def _build_fast_indexes(self) -> None:
        """Extracts executable segments into memory to build instant opcode & ADRP tables across all segments."""
        from java.lang.reflect import Array
        from java.lang import Byte
        import re

        try:
            mem = self.program.getMemory()
            candidate_blocks = []
            for blk in mem.getBlocks():
                try:
                    is_exec = (hasattr(blk, "isExecute") and blk.isExecute())
                except Exception:
                    is_exec = False
                sz = int(blk.getSize())
                if is_exec or sz > 4096:
                    candidate_blocks.append(blk)
            if not candidate_blocks:
                b = mem.getBlock(self.flat_api.toAddr(self.image_base))
                if b and int(b.getSize()) > 0:
                    candidate_blocks = [b]
                else:
                    candidate_blocks = [blk for blk in mem.getBlocks() if int(blk.getSize()) > 0]

            if not candidate_blocks:
                return

            gates = []
            adrp_dict: Dict[int, List[Dict[str, Any]]] = {}
            pattern_op = re.compile(b"([\x00-\xe0][\x00-\xff][\x80-\x9f]\x52)\xc0\x03\x5f\xd6")

            for b in candidate_blocks:
                try:
                    size = int(b.getSize())
                    if size < 8:
                        continue
                    jbytes = Array.newInstance(Byte.TYPE, size)
                    mem.getBytes(b.getStart(), jbytes)
                    raw = bytes(jbytes)
                    base_va = b.getStart().getOffset()

                    # 1. Opcode gates: movz w0, #imm; ret
                    for m in pattern_op.finditer(raw):
                        offset = m.start()
                        b0 = raw[offset]
                        b1 = raw[offset + 1]
                        b2 = raw[offset + 2]
                        imm = ((b0 >> 5) & 7) | (b1 << 3) | ((b2 & 0x1f) << 11)
                        va = base_va + offset
                        rva = va - self.image_base
                        gates.append((imm, va, rva))

                    # 2. ADRP instructions: GPUAdrpScanner with fallback
                    gpu_scanned = False
                    try:
                        import numpy as np
                        from gpu_adrp_scanner import GPUAdrpScanner

                        scanner = GPUAdrpScanner(backend="auto")
                        usable_size = size - (size % 4)
                        insn_array = np.frombuffer(raw[:usable_size], dtype="<u4")
                        matches = scanner.scan_matches(insn_array, base_pc=base_va, filter_same_register=True)

                        for m in matches:
                            target_page = m.resolved_target & ~0xFFF
                            if m.paired_type == "ADD":
                                paired_info = f"add x{m.paired_rt}, x{m.paired_rn}, #0x{m.immediate:x}"
                            else:
                                paired_info = f"ldr x{m.paired_rt}, [x{m.paired_rn}, #0x{m.immediate:x}]"

                            if target_page not in adrp_dict:
                                adrp_dict[target_page] = []
                            adrp_dict[target_page].append({
                                "insn_va": m.adrp_pc,
                                "insn_rva": m.adrp_pc - self.image_base,
                                "rd": m.adrp_rd,
                                "target_page": target_page,
                                "paired_offset": m.immediate,
                                "paired_info": paired_info,
                            })
                        gpu_scanned = True
                    except Exception as e:
                        logger.debug(f"GPUAdrpScanner fallback to pure-Python: {e}")

                    if not gpu_scanned:
                        for offset in range(0, size - 8, 4):
                            inst = struct.unpack_from("<I", raw, offset)[0]
                            if (inst & 0x9F000000) == 0x90000000:
                                rd = inst & 0x1F
                                immlo = (inst >> 29) & 0x3
                                immhi = (inst >> 5) & 0x7FFFF
                                imm = (immhi << 2) | immlo
                                if imm & (1 << 20):
                                    imm -= (1 << 21)
                                pc = base_va + offset
                                pc_page = pc & ~0xFFF
                                target_page = pc_page + (imm << 12)

                                # Inspect next instruction (paired add or ldr)
                                next_inst = struct.unpack_from("<I", raw, offset + 4)[0]
                                paired_info = None
                                paired_offset = None
                                if (next_inst & 0x7F800000) == 0x11000000 and ((next_inst >> 5) & 0x1F) == rd:
                                    paired_offset = (next_inst >> 10) & 0xFFF
                                    paired_info = f"add x{next_inst & 0x1F}, x{rd}, #0x{paired_offset:x}"
                                elif (next_inst & 0xFFC00000) == 0xF9400000 and ((next_inst >> 5) & 0x1F) == rd:
                                    shift = (next_inst >> 30) & 0x3
                                    paired_offset = ((next_inst >> 10) & 0xFFF) << shift
                                    paired_info = f"ldr x{next_inst & 0x1F}, [x{rd}, #0x{paired_offset:x}]"

                                if target_page not in adrp_dict:
                                    adrp_dict[target_page] = []
                                adrp_dict[target_page].append({
                                    "insn_va": pc,
                                    "insn_rva": pc - self.image_base,
                                    "rd": rd,
                                    "target_page": target_page,
                                    "paired_offset": paired_offset,
                                    "paired_info": paired_info,
                                })
                except Exception as b_err:
                    logger.debug(f"Error scanning segment {b}: {b_err}")

            self._opcode_gates = gates
            self._adrp_pages = adrp_dict

            logger.info(
                f"Warmed up indexes: {len(self._opcode_gates)} opcode gates, "
                f"{len(self._adrp_pages)} unique ADRP target pages indexed across {len(candidate_blocks)} segments."
            )
        except Exception as e:
            logger.warning(f"Error during fast index building: {e}")


    # --------------------------------------------------------------------------
    # Core Queries
    # --------------------------------------------------------------------------

    def query_rva(self, addr_input: Any) -> Dict[str, Any]:
        """Instant VA <-> RVA translation (<1 ms, zero JVM call)."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                t0 = time.perf_counter()
                va, rva = normalize_address_pair(addr_input, self.image_base)
                t_ms = (time.perf_counter() - t0) * 1000.0
                return {
                    "status": "ok",
                    "va": f"0x{va:08X}",
                    "rva": f"0x{rva:08X}",
                    "va_int": va,
                    "rva_int": rva,
                    "image_base": f"0x{self.image_base:08X}",
                    "time_ms": round(t_ms, 4),
                }
            finally:
                self.last_decompile_time = time.time()

    def query_decompile(
        self,
        targets: List[Any],
        style: Optional[str] = None,
        throttle_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Returns decompiled C code, mapping Ghidra VA and runtime RVA."""
        with self._engine_lock:
            self._ensure_decompiler_active()
            self.last_decompile_time = time.time()
            try:
                # Apply simplification style (Section 8.3)
                simplification = style or ("normalize" if self.resource_mode == "eco" else "decompile")
                decomp_style = style or simplification
                try:
                    self.decompiler.setSimplificationStyle(simplification)
                except Exception as e:
                    logger.debug(f"Could not set simplification style '{simplification}': {e}")

                effective_throttle_ms = throttle_ms if throttle_ms is not None else self.throttle_ms
                results = []

                for idx, t in enumerate(targets):
                    if idx > 0 and effective_throttle_ms > 0:
                        time.sleep(effective_throttle_ms / 1000.0)

                    va, rva = normalize_address_pair(t, self.image_base)
                    cached = self.decompile_cache.get((va, decomp_style))
                    if cached is not None:
                        cached_copy = dict(cached)
                        if "code" in cached_copy:
                            cached_copy["code"] = self.overlay.apply_to_c_code(cached_copy["code"], self.image_base)
                        cached_copy["cached"] = True
                        results.append(cached_copy)
                        continue

                    addr = self.flat_api.toAddr(va)
                    fm = self.program.getFunctionManager()
                    func = fm.getFunctionAt(addr)
                    if not func:
                        func = fm.getFunctionContaining(addr)

                    if func is None:
                        entry = {
                            "target": str(t),
                            "va": f"0x{va:08X}",
                            "rva": f"0x{rva:08X}",
                            "error": "Could not locate or disassemble function at address",
                        }
                        results.append(entry)
                        continue

                    # Dynamic per-function complexity downshifting
                    effective_style = simplification
                    if style is None and DecompilerComplexityGovernor is not None:
                        try:
                            body_size = int(func.getBody().getNumAddresses()) if hasattr(func, "getBody") and func.getBody() else 0
                            mode_enum = ResourceMode(self.resource_mode.lower()) if ResourceMode else None
                            if mode_enum and get_default_mode_policy:
                                policy = get_default_mode_policy(mode_enum)
                                dyn_style, _ = DecompilerComplexityGovernor.resolve_simplification_style(
                                    policy,
                                    body_size_bytes=body_size,
                                    basic_block_count=0,
                                    is_cpu_throttled=(self.resource_mode == "eco"),
                                )
                                if dyn_style:
                                    effective_style = dyn_style
                        except Exception as e:
                            logger.debug(f"Complexity governor resolution failed: {e}")

                    try:
                        self.decompiler.setSimplificationStyle(effective_style)
                    except Exception as e:
                        logger.debug(f"Could not set simplification style '{effective_style}': {e}")

                    try:
                        res = self.decompiler.decompileFunction(func, 45, self.monitor)
                        if res.decompileCompleted():
                            raw_c_code = res.getDecompiledFunction().getC()
                            entry_addr = func.getEntryPoint().getOffset()
                            entry_rva = entry_addr - self.image_base
                            fn_name = self.overlay.get_rename(entry_addr, entry_rva) or func.getName()
                            comment = self.overlay.get_comment(entry_addr, entry_rva)

                            # Register caller and discovered callees in self.dep_dag
                            caller_fid = f"0x{entry_addr:08X}"
                            self.dep_dag.add_function(caller_fid, address=entry_addr, name=fn_name)

                            # Record all callees by address
                            discovered_callees: Set[Tuple[int, Optional[str]]] = set()
                            try:
                                if hasattr(func, "getCalledFunctions"):
                                    for cf in func.getCalledFunctions(self.monitor):
                                        if cf and hasattr(cf, "getEntryPoint"):
                                            c_addr = cf.getEntryPoint().getOffset()
                                            c_name = cf.getName() if hasattr(cf, "getName") else None
                                            discovered_callees.add((c_addr, c_name))
                            except Exception as e:
                                logger.debug(f"func.getCalledFunctions notice: {e}")

                            # Also scan C code for FUN_<hex> callees
                            for callee_hex in re.findall(r"\bFUN_([0-9a-fA-F]{8})\b", raw_c_code, flags=re.IGNORECASE):
                                try:
                                    c_val = int(callee_hex, 16)
                                    c_va = c_val if c_val >= self.image_base else (c_val + self.image_base)
                                    discovered_callees.add((c_va, f"FUN_{callee_hex}"))
                                except Exception:
                                    pass

                            # Also check known named functions from dep_dag
                            for node in list(self.dep_dag.functions.values()):
                                if node.name and len(node.name) >= 3 and node.address is not None:
                                    if re.search(r"\b" + re.escape(node.name) + r"\b", raw_c_code):
                                        discovered_callees.add((node.address, node.name))

                            for c_va, c_name in discovered_callees:
                                try:
                                    callee_fid = f"0x{c_va:08X}"
                                    self.dep_dag.add_function(callee_fid, address=c_va, name=c_name)
                                    self.dep_dag.add_call_edge(caller_fid, callee_fid)
                                except Exception:
                                    pass

                            # Apply write overlay renames to decompiled C body
                            c_code = self.overlay.apply_to_c_code(raw_c_code, self.image_base)

                            data = {
                                "target": str(t),
                                "va": f"0x{va:08X}",
                                "rva": f"0x{rva:08X}",
                                "name": fn_name,
                                "entry_va": f"0x{entry_addr:08X}",
                                "entry_rva": f"0x{entry_rva:08X}",
                                "code": c_code,
                                "comment": comment,
                                "style": effective_style,
                                "cached": False,
                            }
                            self.decompile_cache.put((va, decomp_style), data)
                            try:
                                self.dep_dag.cache.put(caller_fid, c_code)
                            except Exception:
                                pass
                            results.append(data)

                        else:
                            results.append({
                                "target": str(t),
                                "va": f"0x{va:08X}",
                                "rva": f"0x{rva:08X}",
                                "error": res.getErrorMessage(),
                            })
                    finally:
                        if effective_style != simplification:
                            try:
                                self.decompiler.setSimplificationStyle(simplification)
                            except Exception:
                                pass

                return {"status": "ok", "results": results}
            finally:
                self.last_decompile_time = time.time()

    def query_vtable(self, target: Any, count: int = 12) -> Dict[str, Any]:
        """Dumps VTable slots, function names, and runtime hook RVAs."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                vt_va, vt_rva = normalize_address_pair(target, self.image_base)
                cache_key = (vt_va, count)
                cached = self.vtable_cache.get(cache_key)
                if cached is not None:
                    c = dict(cached)
                    c["cached"] = True
                    return c

                addr = self.flat_api.toAddr(vt_va)
                mem = self.program.getMemory()
                fm = self.program.getFunctionManager()
                af = self.program.getAddressFactory().getDefaultAddressSpace()

                entries = []
                for i in range(count):
                    slot_va = vt_va + (i * 8)
                    slot_rva = vt_rva + (i * 8)
                    try:
                        fn_ptr = mem.getLong(af.getAddress(slot_va))
                        fn_va = fn_ptr
                        fn_rva = fn_ptr - self.image_base if fn_ptr >= self.image_base else fn_ptr
                        fn = fm.getFunctionAt(af.getAddress(fn_va))
                        fn_name = (
                            self.overlay.get_rename(fn_va, fn_rva)
                            or (fn.getName() if fn else None)
                            or "None"
                        )
                        slot_comment = self.overlay.get_comment(slot_va, slot_rva)
                        entries.append({
                            "slot": i,
                            "slot_va": f"0x{slot_va:08X}",
                            "slot_rva": f"0x{slot_rva:08X}",
                            "fn_va": f"0x{fn_va:08X}",
                            "fn_rva": f"0x{fn_rva:08X}",
                            "name": fn_name,
                            "comment": slot_comment,
                        })
                    except Exception as e:
                        entries.append({
                            "slot": i,
                            "slot_va": f"0x{slot_va:08X}",
                            "slot_rva": f"0x{slot_rva:08X}",
                            "error": str(e),
                        })

                vt_name = self.overlay.get_rename(vt_va, vt_rva)
                result = {
                    "status": "ok",
                    "vtable_va": f"0x{vt_va:08X}",
                    "vtable_rva": f"0x{vt_rva:08X}",
                    "name": vt_name,
                    "count": count,
                    "entries": entries,
                    "cached": False,
                }
                self.vtable_cache.put(cache_key, result)
                return result
            finally:
                self.last_decompile_time = time.time()

    def query_disassemble(self, target: Any, count: int = 30) -> Dict[str, Any]:
        """Returns instruction disassembly, hex bytes, and operands."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                va, rva = normalize_address_pair(target, self.image_base)
                addr = self.flat_api.toAddr(va)
                listing = self.program.getListing()

                rows = []
                for insn in listing.getInstructions(addr, True):
                    if len(rows) >= count:
                        break
                    insn_va = insn.getAddress().getOffset()
                    insn_rva = insn_va - self.image_base
                    raw_hex = bytes([b & 0xFF for b in insn.getBytes()]).hex()
                    ops = [
                        insn.getDefaultOperandRepresentation(i)
                        for i in range(insn.getNumOperands())
                    ]
                    comment = self.overlay.get_comment(insn_va, insn_rva)
                    rows.append({
                        "va": f"0x{insn_va:08X}",
                        "rva": f"0x{insn_rva:08X}",
                        "bytes": raw_hex,
                        "mnemonic": insn.getMnemonicString(),
                        "operands": ", ".join(filter(None, ops)),
                        "comment": comment,
                    })

                return {
                    "status": "ok",
                    "target_va": f"0x{va:08X}",
                    "target_rva": f"0x{rva:08X}",
                    "count": len(rows),
                    "instructions": rows,
                }
            finally:
                self.last_decompile_time = time.time()

    def query_refs(self, target: Any, max_count: int = 20) -> Dict[str, Any]:
        """Queries incoming cross-references with caller function names."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                va, rva = normalize_address_pair(target, self.image_base)
                addr = self.flat_api.toAddr(va)
                ref_mgr = self.program.getReferenceManager()
                fm = self.program.getFunctionManager()

                refs = list(ref_mgr.getReferencesTo(addr))
                entries = []
                for r in refs[:max_count]:
                    from_addr = r.getFromAddress()
                    from_va = from_addr.getOffset()
                    from_rva = from_va - self.image_base
                    fn = fm.getFunctionContaining(from_addr)
                    caller_name = None
                    caller_va = None
                    caller_rva = None
                    if fn:
                        caller_va = fn.getEntryPoint().getOffset()
                        caller_rva = caller_va - self.image_base
                        caller_name = self.overlay.get_rename(caller_va, caller_rva) or fn.getName()

                    comment = self.overlay.get_comment(from_va, from_rva)
                    entries.append({
                        "from_va": f"0x{from_va:08X}",
                        "from_rva": f"0x{from_rva:08X}",
                        "ref_type": str(r.getReferenceType()),
                        "caller_name": caller_name or "None",
                        "caller_entry_va": f"0x{caller_va:08X}" if caller_va else None,
                        "caller_entry_rva": f"0x{caller_rva:08X}" if caller_rva else None,
                        "comment": comment,
                    })

                return {
                    "status": "ok",
                    "target_va": f"0x{va:08X}",
                    "target_rva": f"0x{rva:08X}",
                    "total_refs": len(refs),
                    "count": len(entries),
                    "references": entries,
                }
            finally:
                self.last_decompile_time = time.time()

    def query_adrp_add(self, symbol_or_addr: str) -> Dict[str, Any]:
        """Fast lookup for PC-relative string and pointer references via cached page index."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                target_va = None
                target_sym = None

                # Check if input is symbol name
                s = symbol_or_addr.strip()
                is_num = False
                try:
                    if s.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s):
                        target_va, _ = normalize_address_pair(s, self.image_base)
                        is_num = True
                except Exception:
                    pass

                if not is_num:
                    target_sym = s
                    # Search symbol table
                    sym_tab = self.program.getSymbolTable()
                    syms = list(sym_tab.getGlobalSymbols(s))
                    if syms:
                        target_va = syms[0].getAddress().getOffset()
                    else:
                        # Check write-overlay
                        for k, v in self.overlay.renames.items():
                            if v == s:
                                target_va, _ = normalize_address_pair(k, self.image_base)
                                break

                if target_va is None:
                    return {"status": "error", "message": f"Symbol or address '{symbol_or_addr}' could not be resolved"}

                target_rva = target_va - self.image_base
                target_page = target_va & ~0xFFF
                target_offset = target_va & 0xFFF

                fm = self.program.getFunctionManager()
                ref_mgr = self.program.getReferenceManager()

                # 1. References from Ghidra reference manager
                direct_refs = []
                for r in ref_mgr.getReferencesTo(self.flat_api.toAddr(target_va)):
                    f_addr = r.getFromAddress()
                    f_va = f_addr.getOffset()
                    f_rva = f_va - self.image_base
                    fn = fm.getFunctionContaining(f_addr)
                    direct_refs.append({
                        "source": "ReferenceManager",
                        "insn_va": f"0x{f_va:08X}",
                        "insn_rva": f"0x{f_rva:08X}",
                        "ref_type": str(r.getReferenceType()),
                        "caller": fn.getName() if fn else "None",
                    })

                # 2. Fast Page Index lookup
                page_refs = []
                if target_page in self._adrp_pages:
                    for item in self._adrp_pages[target_page]:
                        p_offset = item.get("paired_offset")
                        is_exact = (p_offset == target_offset)
                        f_va = item["insn_va"]
                        fn = fm.getFunctionContaining(self.flat_api.toAddr(f_va))
                        page_refs.append({
                            "source": "ADRPPageIndex",
                            "insn_va": f"0x{f_va:08X}",
                            "insn_rva": f"0x{item['insn_rva']:08X}",
                            "register": f"x{item['rd']}",
                            "target_page": f"0x{target_page:08X}",
                            "paired_insn": item.get("paired_info"),
                            "exact_offset_match": is_exact,
                            "caller": fn.getName() if fn else "None",
                        })

                return {
                    "status": "ok",
                    "symbol": target_sym,
                    "target_va": f"0x{target_va:08X}",
                    "target_rva": f"0x{target_rva:08X}",
                    "target_page": f"0x{target_page:08X}",
                    "target_offset": f"0x{target_offset:03X}",
                    "direct_refs_count": len(direct_refs),
                    "page_refs_count": len(page_refs),
                    "direct_references": direct_refs,
                    "page_references": page_refs,
                }
            finally:
                self.last_decompile_time = time.time()

    def query_opcodes(self, min_op: int, max_op: int) -> Dict[str, Any]:
        """Fast opcode enumeration for `mov w0, #imm; ret` dispatcher gates."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                matches = []
                fm = self.program.getFunctionManager()
                for imm, va, rva in self._opcode_gates:
                    if min_op <= imm <= max_op:
                        fn = fm.getFunctionAt(self.flat_api.toAddr(va))
                        fn_name = (
                            self.overlay.get_rename(va, rva)
                            or (fn.getName() if fn else None)
                        )
                        comment = self.overlay.get_comment(va, rva)
                        matches.append({
                            "opcode": imm,
                            "opcode_hex": f"0x{imm:04X}",
                            "va": f"0x{va:08X}",
                            "rva": f"0x{rva:08X}",
                            "func_name": fn_name,
                            "comment": comment,
                            "asm": f"mov w0, #0x{imm:x}; ret",
                        })

                matches.sort(key=lambda x: x["opcode"])
                return {
                    "status": "ok",
                    "min": min_op,
                    "max": max_op,
                    "count": len(matches),
                    "total_indexed_gates": len(self._opcode_gates),
                    "gates": matches,
                }
            finally:
                self.last_decompile_time = time.time()

    def query_status(self) -> Dict[str, Any]:
        """Reports daemon uptime, function count, and LRU cache hit rate."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                uptime = time.time() - self.start_time
                fm = self.program.getFunctionManager()
                func_count = fm.getFunctionCount()

                d_stats = self.decompile_cache.stats()
                v_stats = self.vtable_cache.stats()
                total_hits = d_stats["hits"] + v_stats["hits"]
                total_queries = total_hits + d_stats["misses"] + v_stats["misses"]
                overall_hit_rate = (
                    round((total_hits / total_queries * 100.0), 2)
                    if total_queries > 0
                    else 0.0
                )

                return {
                    "status": "ok",
                    "uptime_seconds": round(uptime, 2),
                    "uptime_human": f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s",
                    "resource_mode": self.resource_mode,
                    "is_hibernating": self.is_hibernating,
                    "project_name": self.project_name,
                    "project_dir": self.project_dir,
                    "program_name": self.program_name,
                    "image_base": f"0x{self.image_base:08X}",
                    "function_count": func_count,
                    "indexed_opcode_gates": len(self._opcode_gates),
                    "indexed_adrp_pages": len(self._adrp_pages),
                    "decompile_cache": d_stats,
                    "vtable_cache": v_stats,
                    "overall_hit_rate_pct": overall_hit_rate,
                    "overlay_renames_count": len(self.overlay.renames),
                    "overlay_comments_count": len(self.overlay.comments),
                    "l2_cache_count": self.l2_cache.count(),
                }
            finally:
                self.last_decompile_time = time.time()

    def invalidate_function_cache(self, addr: Any) -> Any:
        """
        Executes 1-hop selective cache invalidation via DependencyCacheDAG.
        Evicts target function and its direct 1-hop callers from self.decompile_cache, self.vtable_cache, and self.l2_cache.
        """
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                try:
                    va = parse_addr_int(addr)
                    fid = f"0x{va:08X}"
                except (ValueError, TypeError):
                    va = None
                    fid = str(addr).strip()

                report = None
                if hasattr(self.dep_dag, "invalidate_function"):
                    report = self.dep_dag.invalidate_function(fid)
                elif hasattr(self.dep_dag, "invalidate_function_signature"):
                    report = self.dep_dag.invalidate_function_signature(fid)

                # Evict target and 1-hop callers from decompile_cache (L1), vtable_cache (L1) and l2_cache (L2)
                affected_set = set(report.affected_functions) if report else set()
                affected_set.add(fid)

                prog_id = self.program_id or None
                for aff in affected_set:
                    aff_va = None
                    try:
                        aff_va = parse_addr_int(aff)
                    except Exception:
                        node = self.dep_dag.functions.get(aff)
                        if node and node.address is not None:
                            aff_va = node.address

                    if aff_va is not None:
                        self.decompile_cache.evict(aff_va)
                        self.vtable_cache.evict(aff_va)
                        self.l2_cache.invalidate_address(aff_va, program_id=prog_id)
                    self.decompile_cache.evict(aff)
                    self.vtable_cache.evict(aff)

                if va is not None:
                    self.decompile_cache.evict(va)
                    self.vtable_cache.evict(va)
                    self.l2_cache.invalidate_address(va, program_id=prog_id)

                return report
            finally:
                self.last_decompile_time = time.time()

    def set_rename(self, addr: Any, new_name: str, old_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Sets function rename in WriteOverlay, records mutation in SemanticDeltaLog,
        and performs 1-hop selective cache invalidation.
        """
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                try:
                    va = parse_addr_int(addr)
                    norm_key = normalize_hex_key(va)
                    old_n = old_name or self.overlay.renames.get(norm_key, f"FUN_{va:08X}")
                except (ValueError, TypeError):
                    va = None
                    norm_key = str(addr).strip()
                    old_n = old_name or norm_key

                self.overlay.set_rename(addr, new_name)
                if hasattr(self.delta_log, "record_function_rename"):
                    self.delta_log.record_function_rename(va, new_name, old_name=old_n)
                elif SemanticEvent is not None:
                    evt = SemanticEvent.create_rename_symbol(
                        old_name=old_n,
                        new_name=new_name,
                        target_address=va,
                        symbol_type="FUNCTION",
                    )
                    self.delta_log.append(evt)

                report = self.invalidate_function_cache(addr)
                return {
                    "status": "ok",
                    "message": f"Renamed {norm_key} to '{new_name}'",
                    "invalidation_report": report.to_dict() if hasattr(report, "to_dict") else None,
                }
            finally:
                self.last_decompile_time = time.time()

    def set_comment(self, addr: Any, comment: str, comment_type: str = "EOL") -> Dict[str, Any]:
        """
        Sets address comment in WriteOverlay, records mutation in SemanticDeltaLog,
        and invalidates function cache.
        """
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                try:
                    va = parse_addr_int(addr)
                    norm_key = normalize_hex_key(va)
                except (ValueError, TypeError):
                    va = None
                    norm_key = str(addr).strip()

                self.overlay.set_comment(addr, comment)
                if hasattr(self.delta_log, "record_comment"):
                    self.delta_log.record_comment(va, comment, comment_type=comment_type)
                elif SemanticEvent is not None:
                    evt = SemanticEvent.create_set_comment(
                        comment_text=comment,
                        target_address=va,
                        comment_type=comment_type,
                    )
                    self.delta_log.append(evt)

                report = self.invalidate_function_cache(addr)
                return {
                    "status": "ok",
                    "message": f"Set comment on {norm_key}",
                    "invalidation_report": report.to_dict() if hasattr(report, "to_dict") else None,
                }
            finally:
                self.last_decompile_time = time.time()

    def query_type(self, name_or_id: str) -> Dict[str, Any]:
        """Queries the off-heap deduplicated type store for layout and C declaration."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                res = self.type_adapter.handle_oracle_command("type", [name_or_id])
                if res.get("status") == "ok":
                    res["layout"] = self.type_store.get_struct_layout(name_or_id)
                return res
            finally:
                self.last_decompile_time = time.time()

    def register_struct(
        self, name: str, byte_size: int, members: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Registers a deduplicated struct in the off-heap SQLite type store."""
        with self._engine_lock:
            self.last_decompile_time = time.time()
            try:
                struct_members = []
                for m in members:
                    struct_members.append(
                        StructMember(
                            name=m.get("name", f"field_{m.get('offset', 0):x}"),
                            type_id=m.get("type_id", "void*"),
                            offset=int(m.get("offset", 0)),
                            size=int(m.get("size", 4)),
                            bit_size=m.get("bit_size"),
                            bit_offset=m.get("bit_offset"),
                            access=m.get("access", "public"),
                        )
                    )
                align = max([m.size for m in struct_members], default=4) if struct_members else 4
                dedup = TypeDeduplicator()
                norm_type = dedup.register_type(
                    name=name,
                    kind=TypeKind.STRUCT,
                    byte_size=byte_size,
                    alignment=align,
                    members=struct_members,
                )
                cursor = self.type_store._conn.cursor()
                cursor.execute("DELETE FROM struct_members WHERE owner_type_id = ?", (norm_type.type_id,))
                self.type_store._conn.commit()

                self.type_store.ingest_from_deduplicator(dedup)
                return {
                    "status": "ok",
                    "type_id": norm_type.type_id,
                    "name": norm_type.name,
                    "byte_size": norm_type.byte_size,
                    "members_count": len(norm_type.members),
                    "fingerprint": norm_type.fingerprint,
                    "layout": self.type_store.get_struct_layout(norm_type.type_id),
                    "c_decl": self.type_store.render_c_declaration(norm_type.type_id),
                }
            finally:
                self.last_decompile_time = time.time()




# ==============================================================================
# Mock Ghidra Oracle Session (Standalone Offline Core)
# ==============================================================================

class MockGhidraOracleSession:
    """Standalone in-memory mock oracle session for running and testing the daemon without Ghidra/JVM."""

    def __init__(
        self,
        resource_mode: str = "balanced",
        overlay: Optional[WriteOverlay] = None,
        l2_cache: Optional[L2SQLiteCache] = None,
    ):
        self.project_dir = "mock_project_dir"
        self.project_name = "mock_project"
        self.program_name = "mock_program"
        self.image_base = DEFAULT_IMAGE_BASE
        self.resource_mode = resource_mode
        self.overlay = overlay if overlay is not None else WriteOverlay()
        self.l2_cache = l2_cache if l2_cache is not None else L2SQLiteCache()
        self.start_time = time.time()
        self.decompile_cache = LRUCache(512)
        self.vtable_cache = LRUCache(512)
        self.type_store = OffHeapTypeStore()
        self.is_hibernating = False
        self.throttle_ms = 10

    def initialize(self) -> None:
        pass

    def close(self) -> None:
        pass

    def query_rva(self, addr: Any) -> Dict[str, Any]:
        val = parse_addr_int(addr)
        return {
            "status": "ok",
            "va": normalize_hex_key(val),
            "rva": f"0x{va_to_rva(val):08X}",
            "time_ms": 0.05,
        }

    def query_decompile(self, targets: Sequence[Any], style: str = "ghidra", throttle_ms: Optional[int] = None) -> Dict[str, Any]:
        funcs = []
        for t in targets:
            addr_int = parse_addr_int(t)
            code = (
                f"// Mock decompilation for {normalize_hex_key(addr_int)} (SuperGhidra standalone mode)\n"
                f"int func_{addr_int:08X}(int a1, int a2) {{\n"
                f"    return (a1 * 2) + a2;\n"
                f"}}\n"
            )
            funcs.append({
                "va": normalize_hex_key(addr_int),
                "rva": f"0x{va_to_rva(addr_int):08X}",
                "name": f"func_{addr_int:08X}",
                "code": code,
                "time_ms": 0.5,
            })
        return {
            "status": "ok",
            "targets": list(targets),
            "style": style,
            "functions": funcs,
            "time_ms": 1.0,
        }

    def query_vtable(self, addr: Any, count: int = 12) -> Dict[str, Any]:
        base_addr = parse_addr_int(addr)
        slots = [
            {
                "slot": i,
                "va": f"0x{base_addr + i * 8:08X}",
                "target": f"0x{0x00401000 + i * 0x20:08X}",
                "name": f"vfunc_{i}",
            }
            for i in range(count)
        ]
        return {
            "status": "ok",
            "target_va": normalize_hex_key(base_addr),
            "target_rva": f"0x{va_to_rva(base_addr):08X}",
            "vtable": slots,
            "time_ms": 0.5,
        }

    def query_disassemble(self, addr: Any, count: int = 30) -> Dict[str, Any]:
        base_addr = parse_addr_int(addr)
        insns = []
        for i in range(count):
            insns.append({
                "va": f"0x{base_addr + i * 4:08X}",
                "rva": f"0x{va_to_rva(base_addr + i * 4):08X}",
                "bytes": "E00300AA",
                "mnemonic": "mov",
                "operands": f"x0, x{i % 8}",
                "comment": "",
            })
        return {
            "status": "ok",
            "target_va": normalize_hex_key(base_addr),
            "target_rva": f"0x{va_to_rva(base_addr):08X}",
            "count": len(insns),
            "instructions": insns,
            "time_ms": 0.5,
        }

    def query_refs(self, addr: Any, count: int = 20) -> Dict[str, Any]:
        base_addr = parse_addr_int(addr)
        refs = [
            {
                "from_va": f"0x{base_addr - 0x100 + i * 0x20:08X}",
                "from_rva": f"0x{va_to_rva(base_addr - 0x100 + i * 0x20):08X}",
                "ref_type": "DATA",
                "caller_name": "None",
                "caller_entry_rva": "0x00000000",
            }
            for i in range(min(count, 5))
        ]
        return {
            "status": "ok",
            "target_va": normalize_hex_key(base_addr),
            "target_rva": f"0x{va_to_rva(base_addr):08X}",
            "total_refs": len(refs),
            "references": refs,
            "time_ms": 0.5,
        }

    def query_adrp_add(self, target: str) -> Dict[str, Any]:
        return {
            "status": "ok",
            "target": target,
            "count": 0,
            "pairs": [],
            "time_ms": 0.2,
        }

    def query_opcodes(self, min_op: int = 500, max_op: int = 550) -> Dict[str, Any]:
        return {
            "status": "ok",
            "min_opcodes": min_op,
            "max_opcodes": max_op,
            "count": 0,
            "functions": [],
            "time_ms": 0.2,
        }

    def hibernate(self) -> Dict[str, Any]:
        return {"status": "ok", "state": "hibernated", "mode": self.resource_mode}

    def set_resource_mode(self, new_mode: str) -> Dict[str, Any]:
        self.resource_mode = new_mode
        return {"status": "ok", "mode": new_mode}

    def set_rename(self, addr: Any, name: str, old_name: Optional[str] = None) -> Dict[str, Any]:
        hex_addr = normalize_hex_key(addr)
        self.overlay.set_rename(hex_addr, name)
        return {"status": "ok", "addr": hex_addr, "new_name": name}

    def set_comment(self, addr: Any, comment: str, comment_type: str = "eol") -> Dict[str, Any]:
        hex_addr = normalize_hex_key(addr)
        self.overlay.set_comment(hex_addr, comment)
        return {"status": "ok", "addr": hex_addr, "comment": comment}

    def query_type(self, name_or_id: str) -> Dict[str, Any]:
        return {
            "status": "ok",
            "type": {"name": str(name_or_id), "size": 8},
            "c_decl": f"struct {name_or_id} {{ void* vptr; }};",
        }

    def register_struct(self, name: str, byte_size: int, members: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "status": "ok",
            "name": name,
            "byte_size": byte_size,
            "type_id": 1001,
            "c_decl": f"struct {name} {{ char _buf[{byte_size}]; }};",
        }

    def query_status(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "initialized": True,
            "mock_mode": True,
            "mode": self.resource_mode,
            "program_name": self.program_name,
            "project_name": self.project_name,
            "project_dir": self.project_dir,
            "image_base": f"0x{self.image_base:08X}",
            "function_count": 42,
            "indexed_opcode_gates": 0,
            "indexed_adrp_pages": 0,
            "decompile_cache": {"size": 0, "capacity": 512, "hit_rate_pct": 0.0, "hits": 0, "misses": 0},
            "vtable_cache": {"size": 0, "capacity": 512, "hit_rate_pct": 0.0, "hits": 0, "misses": 0},
            "l2_cache_count": 0,
            "overall_hit_rate_pct": 0.0,
            "overlay_renames_count": len(self.overlay.renames),
            "overlay_comments_count": len(self.overlay.comments),
        }


# ==============================================================================
# TCP/JSON Daemon Server
# ==============================================================================

class GhidraDaemonServer:
    """Threaded TCP server processing newline-delimited JSON RPC requests."""

    def __init__(
        self,
        session: GhidraOracleSession,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        allow_remote: bool = False,
        token: Optional[str] = None,
    ):
        if not allow_remote and not is_loopback_host(host):
            raise ValueError(
                f"Refusing to bind to non-loopback address '{host}' without allow_remote=True (or --allow-remote)"
            )
        self.session = session
        self.host = host
        self.port = port
        self.allow_remote = allow_remote
        self.token = token
        self.server_socket = None
        self.running = False
        self._threads: List[threading.Thread] = []

    def start(self) -> None:
        if not self.allow_remote and not is_loopback_host(self.host):
            raise ValueError(
                f"Refusing to bind to non-loopback address '{self.host}' without allow_remote=True (or --allow-remote)"
            )
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(16)
        self.running = True
        logger.info(f"Ghidra Oracle daemon listening on {self.host}:{self.port}")
        print(f"[*] Ghidra Oracle daemon online & listening on {self.host}:{self.port}")

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()
                self._threads.append(t)
            except OSError:
                break

    def stop(self) -> None:
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.session.close()
        logger.info("Ghidra Oracle daemon shut down cleanly.")

    def _handle_client(self, conn: socket.socket, addr: Any) -> None:
        with conn:
            conn.settimeout(60.0)
            buffer = bytearray()
            while self.running:
                try:
                    data = conn.recv(8192)
                    if not data:
                        break
                    buffer.extend(data)

                    # Limit request size to prevent memory exhaustion
                    if len(buffer) > MAX_REQUEST_SIZE:
                        logger.warning(
                            f"Closing connection: incoming buffer size ({len(buffer)} bytes) "
                            f"exceeds MAX_REQUEST_SIZE ({MAX_REQUEST_SIZE} bytes) from {addr}"
                        )
                        err_resp = {
                            "status": "error",
                            "message": "Request payload exceeds maximum allowed size",
                        }
                        try:
                            conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
                        except Exception:
                            pass
                        return

                    while b"\n" in buffer:
                        idx = buffer.index(b"\n")
                        line_bytes = bytes(buffer[:idx]).strip()
                        del buffer[:idx + 1]
                        if not line_bytes:
                            continue

                        # Reject cross-protocol attacks (e.g. browser HTTP POST to 127.0.0.1:5073)
                        for http_method in (b"GET ", b"POST ", b"OPTIONS ", b"PUT ", b"DELETE ", b"HEAD ", b"TRACE ", b"CONNECT "):
                            if line_bytes.startswith(http_method):
                                logger.warning(f"Closing connection: detected HTTP method prefix from {addr}")
                                return

                        try:
                            line_str = line_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            err_resp = {"status": "error", "message": "Invalid UTF-8 encoding"}
                            try:
                                conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
                            except Exception:
                                pass
                            return

                        try:
                            req = json.loads(line_str)
                        except Exception:
                            err_resp = {"status": "error", "message": "Invalid JSON payload"}
                            try:
                                conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
                            except Exception:
                                pass
                            # Close connection on invalid JSON after first bad line (prevents cross-protocol smuggling)
                            return

                        response = self._dispatch_command(req)
                        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                        if response.get("should_stop"):
                            threading.Thread(target=self.stop, daemon=True).start()
                            return
                except socket.timeout:
                    break
                except Exception as e:
                    err_resp = {"status": "error", "message": str(e)}
                    try:
                        conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
                    except Exception:
                        pass
                    break

    def _dispatch_command(self, req_or_line: Union[Dict[str, Any], str]) -> Dict[str, Any]:
        if isinstance(req_or_line, dict):
            req = req_or_line
        else:
            try:
                req = json.loads(req_or_line)
            except Exception:
                return {"status": "error", "message": "Invalid JSON payload"}

        cmd = req.get("cmd", "").lower()
        args = req.get("args", {})
        if not isinstance(args, dict):
            args = {}

        # Validate session token if server has a token configured
        if self.token is not None:
            req_token = req.get("token")
            if req_token is None and isinstance(args, dict):
                req_token = args.get("token")

            action = args.get("action", req.get("action", "list")) if isinstance(args, dict) else req.get("action", "list")
            is_mutating = (
                cmd in MUTATING_COMMANDS
                or (cmd == "overlay" and action == "clear")
            )

            if is_mutating:
                if not req_token or not secrets.compare_digest(str(req_token), str(self.token)):
                    return {
                        "status": "error",
                        "code": 401,
                        "message": "Unauthorized: invalid or missing session token",
                    }
            else:
                # Read-only command: optional token, but if provided, validate it
                if req_token is not None and not secrets.compare_digest(str(req_token), str(self.token)):
                    return {
                        "status": "error",
                        "code": 401,
                        "message": "Unauthorized: invalid or missing session token",
                    }

        try:
            if cmd == "rva":
                addr = args.get("addr") or req.get("addr")
                return self.session.query_rva(addr)
            elif cmd == "decompile":
                targets = args.get("targets") or req.get("targets") or [args.get("addr")]
                style = args.get("style") or req.get("style")
                throttle = args.get("throttle_ms") or req.get("throttle_ms")
                throttle_int = int(throttle) if throttle is not None else None
                return self.session.query_decompile(targets, style=style, throttle_ms=throttle_int)
            elif cmd == "vtable":
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 12)))
                return self.session.query_vtable(addr, count)
            elif cmd == "disassemble":
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 30)))
                return self.session.query_disassemble(addr, count)
            elif cmd in ("refs", "references"):
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 20)))
                return self.session.query_refs(addr, count)
            elif cmd == "adrp_add":
                target = args.get("target") or req.get("target") or args.get("addr")
                return self.session.query_adrp_add(str(target))
            elif cmd == "opcodes":
                min_op = int(args.get("min", req.get("min", 0)))
                max_op = int(args.get("max", req.get("max", 1000)))
                return self.session.query_opcodes(min_op, max_op)
            elif cmd == "hibernate":
                return self.session.hibernate()
            elif cmd == "mode":
                new_mode = args.get("mode") or req.get("mode") or args.get("arg") or "balanced"
                return self.session.set_resource_mode(str(new_mode))
            elif cmd == "rename":
                addr = args.get("addr")
                name = args.get("name")
                old_name = args.get("old_name")
                return self.session.set_rename(addr, name, old_name=old_name)
            elif cmd == "comment":
                addr = args.get("addr")
                comment = args.get("comment")
                ctype = args.get("comment_type", "EOL")
                return self.session.set_comment(addr, comment, comment_type=ctype)
            elif cmd == "type":
                name_or_id = (
                    args.get("name")
                    or args.get("type_id")
                    or req.get("name")
                    or req.get("type_id")
                    or args.get("name_or_id")
                )
                if not name_or_id and isinstance(args, str):
                    name_or_id = args
                if not name_or_id:
                    return {"status": "error", "message": "Usage: type <name_or_id>"}
                return self.session.query_type(str(name_or_id))
            elif cmd == "register_struct":
                name = args.get("name") or req.get("name")
                byte_size = int(args.get("byte_size", req.get("byte_size", 0)))
                members = args.get("members", req.get("members", []))
                if not name:
                    return {"status": "error", "message": "Missing 'name' for register_struct"}
                return self.session.register_struct(name, byte_size, members)

            elif cmd in ("clear", "clear-cache"):
                self.session.overlay.clear()
                get_client_l2_cache().clear()
                return {"status": "ok", "message": "Write-overlay and L2 cache cleared"}
            elif cmd == "overlay":
                action = args.get("action", req.get("action", "list"))
                if action == "clear":
                    self.session.overlay.clear()
                    return {"status": "ok", "message": "Write-overlay table cleared"}
                return {"status": "ok", "overlay": self.session.overlay.to_dict()}
            elif cmd == "status":
                return self.session.query_status()
            elif cmd == "ping":
                return {"status": "ok", "message": "pong"}
            elif cmd == "stop":
                return {"status": "ok", "message": "Daemon shutting down", "should_stop": True}
            else:
                return {"status": "error", "message": f"Unknown command '{cmd}'"}
        except Exception as e:
            logger.exception(f"Error handling command '{cmd}': {e}")
            return {"status": "error", "message": str(e)}


# ==============================================================================
# Client & Auto-Spawn Daemon Helper
# ==============================================================================

def is_daemon_online(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> bool:
    """Checks if the TCP daemon is reachable."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def spawn_background_daemon(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    token: Optional[str] = None,
    allow_remote: bool = False,
) -> None:
    """Spawns persistent background daemon if offline."""
    script_path = os.path.abspath(__file__)
    log_path = os.path.join(os.path.dirname(script_path), DAEMON_LOG_FILENAME)

    cmd = [sys.executable, script_path, "serve", "--host", host, "--port", str(port)]
    if allow_remote:
        cmd.append("--allow-remote")
    if token:
        cmd.extend(["--token", token])
    print(f"[*] Spawning background Ghidra daemon on {host}:{port}...", file=sys.stderr)

    if os.name == "nt":
        base_flags = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS
            | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
        log_f = open(log_path, "a", encoding="utf-8")
        try:
            # 0x01000000: CREATE_BREAKAWAY_FROM_JOB allows daemon to survive task runner exit
            subprocess.Popen(
                cmd,
                creationflags=base_flags | 0x01000000,
                stdout=log_f,
                stderr=log_f,
                close_fds=True,
            )
        except OSError:
            subprocess.Popen(
                cmd,
                creationflags=base_flags,
                stdout=log_f,
                stderr=log_f,
                close_fds=True,
            )
    else:
        with open(log_path, "a", encoding="utf-8") as log_f:
            subprocess.Popen(
                cmd,
                stdout=log_f,
                stderr=log_f,
                close_fds=True,
                start_new_session=True,
            )


def wait_for_daemon_ready(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = DAEMON_STARTUP_TIMEOUT) -> bool:
    """Waits for the daemon to boot OpenJDK + PyGhidra and accept TCP connections."""
    t0 = time.time()
    print("[*] Warming up JVM & Ghidra project (this takes ~10-15s on first boot)", end="", flush=True, file=sys.stderr)
    while time.time() - t0 < timeout:
        if is_daemon_online(host, port):
            print(" [OK]", file=sys.stderr)
            return True
        print(".", end="", flush=True, file=sys.stderr)
        time.sleep(1.0)
    print(" [TIMEOUT]", file=sys.stderr)
    return False


CACHEABLE_COMMANDS = {
    "decompile",
    "vtable",
    "disassemble",
    "refs",
    "references",
    "adrp_add",
    "opcodes",
}

_client_l2_cache: Optional[L2SQLiteCache] = None


def get_client_l2_cache() -> L2SQLiteCache:
    """Returns singleton L2 SQLite Cache instance for client queries."""
    global _client_l2_cache
    if _client_l2_cache is None:
        _client_l2_cache = L2SQLiteCache()
    return _client_l2_cache


def _make_l2_cache_key(cmd: str, args: Dict[str, Any]) -> Optional[str]:
    """Creates deterministic JSON cache key from query command and arguments."""
    norm_cmd = "refs" if cmd in ("refs", "references") else cmd.lower()
    if norm_cmd not in CACHEABLE_COMMANDS:
        return None

    key_dict: Dict[str, Any] = {}
    if norm_cmd == "decompile":
        raw_targets = args.get("targets")
        if raw_targets is None and "addr" in args:
            raw_targets = [args["addr"]]
        elif raw_targets is None and "target" in args:
            raw_targets = [args["target"]]
        elif isinstance(raw_targets, (str, int)):
            raw_targets = [raw_targets]

        if not raw_targets:
            return None

        norm_targets = []
        for t in raw_targets:
            try:
                norm_targets.append(normalize_hex_key(t))
            except Exception:
                norm_targets.append(str(t).strip().lower())
        key_dict["targets"] = norm_targets
        if args.get("style"):
            key_dict["style"] = str(args["style"]).lower().strip()

    elif norm_cmd in ("vtable", "disassemble", "refs"):
        addr = args.get("addr") or args.get("target")
        if addr is None:
            return None
        try:
            key_dict["addr"] = normalize_hex_key(addr)
        except Exception:
            key_dict["addr"] = str(addr).strip().lower()
        if "count" in args and args["count"] is not None:
            key_dict["count"] = int(args["count"])

    elif norm_cmd == "adrp_add":
        target = args.get("target") or args.get("symbol_or_addr") or args.get("addr")
        if target is None:
            return None
        target_str = str(target).strip()
        try:
            key_dict["target"] = normalize_hex_key(target_str)
        except Exception:
            key_dict["target"] = target_str.lower()

    elif norm_cmd == "opcodes":
        key_dict["min"] = int(args.get("min", 500))
        key_dict["max"] = int(args.get("max", 550))

    return json.dumps(key_dict, sort_keys=True)


def client_send_request(
    cmd: str,
    args: Dict[str, Any],
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    auto_spawn: bool = True,
    l2_cache: Optional[L2SQLiteCache] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Sends JSON-RPC command to the daemon, auto-spawning if offline."""
    t0 = time.perf_counter()
    cmd_lower = cmd.lower()
    resolved_token = load_session_token(token_arg=token)

    # Fast path for rva: zero JVM required (< 0.1 ms)
    if cmd_lower == "rva":
        addr = args.get("addr")
        va, rva = normalize_address_pair(addr, DEFAULT_IMAGE_BASE)
        t_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": "ok",
            "va": f"0x{va:08X}",
            "rva": f"0x{rva:08X}",
            "va_int": va,
            "rva_int": rva,
            "image_base": f"0x{DEFAULT_IMAGE_BASE:08X}",
            "time_ms": round(t_ms, 4),
            "local_fallback": True,
        }

    # 1. Check L2 SQLite cache before TCP connection or daemon spawn
    cache_inst = l2_cache or get_client_l2_cache()
    is_cacheable = cmd_lower in CACHEABLE_COMMANDS
    qtype = "refs" if cmd_lower == "references" else cmd_lower
    cache_key = _make_l2_cache_key(cmd_lower, args) if is_cacheable else None

    if is_cacheable and cache_inst is not None:
        cached_res = None
        if cache_key is not None:
            cached_res = cache_inst.get(qtype, cache_key)
        if cached_res is None:
            # Fallback for direct address or symbol string keys
            raw_key = None
            if cmd_lower == "decompile":
                raw_targets = args.get("targets")
                if raw_targets and isinstance(raw_targets, list) and len(raw_targets) == 1:
                    raw_key = str(raw_targets[0])
                elif raw_targets and isinstance(raw_targets, str):
                    raw_key = raw_targets
                elif args.get("addr"):
                    raw_key = str(args.get("addr"))
            elif cmd_lower in ("vtable", "disassemble", "refs", "references"):
                raw_key = str(args.get("addr") or args.get("target") or "")
            elif cmd_lower == "adrp_add":
                raw_key = str(args.get("target") or args.get("symbol_or_addr") or args.get("addr") or "")
            elif cmd_lower == "opcodes":
                min_op = args.get("min", 500)
                max_op = args.get("max", 550)
                raw_key = f"{min_op}_{max_op}"
            if raw_key:
                cached_res = cache_inst.get(qtype, raw_key)

        if cached_res is not None:
            t_ms = (time.perf_counter() - t0) * 1000.0
            cached_res["l2_cached"] = True
            cached_res["time_ms"] = round(t_ms, 4)

            # Apply WriteOverlay renames and comments on L2 cache hits for decompile queries
            if cmd_lower == "decompile":
                try:
                    overlay = WriteOverlay()
                    img_base = DEFAULT_IMAGE_BASE
                    if "image_base" in cached_res:
                        try:
                            img_base = parse_addr_int(cached_res["image_base"])
                        except Exception:
                            pass
                    elif isinstance(cached_res.get("results"), list) and cached_res["results"]:
                        first = cached_res["results"][0]
                        if isinstance(first, dict) and "va" in first and "rva" in first:
                            try:
                                v_p = parse_addr_int(first["va"])
                                r_p = parse_addr_int(first["rva"])
                                if v_p > r_p:
                                    img_base = v_p - r_p
                            except Exception:
                                pass

                    results = cached_res.get("results")
                    if isinstance(results, list):
                        for item in results:
                            if isinstance(item, dict):
                                c_code = item.get("code")
                                if c_code:
                                    item["code"] = overlay.apply_to_c_code(c_code, img_base)
                                va_val = item.get("entry_va") or item.get("va")
                                rva_val = item.get("entry_rva") or item.get("rva")
                                if va_val is not None:
                                    v_int, r_int = normalize_address_pair(va_val, img_base)
                                    rn = overlay.get_rename(v_int, r_int)
                                    if rn:
                                        item["name"] = rn
                                    cm = overlay.get_comment(v_int, r_int)
                                    if cm:
                                        item["comment"] = cm
                    elif "code" in cached_res:
                        cached_res["code"] = overlay.apply_to_c_code(cached_res["code"], img_base)
                        va_val = cached_res.get("entry_va") or cached_res.get("va")
                        if va_val is not None:
                            v_int, r_int = normalize_address_pair(va_val, img_base)
                            rn = overlay.get_rename(v_int, r_int)
                            if rn:
                                cached_res["name"] = rn
                            cm = overlay.get_comment(v_int, r_int)
                            if cm:
                                cached_res["comment"] = cm
                except Exception as e:
                    logger.debug(f"Failed to apply WriteOverlay to cached decompile result: {e}")

            return cached_res

    if not is_daemon_online(host, port):
        if cmd_lower == "stop":
            return {"status": "ok", "message": "Ghidra daemon is already offline."}
        if cmd_lower == "hibernate":
            return {"status": "ok", "message": "Ghidra daemon is offline (already hibernated)."}
        if not auto_spawn:
            return {"status": "error", "message": f"Ghidra daemon offline on {host}:{port}"}

        spawn_background_daemon(host, port, token=resolved_token)
        if not wait_for_daemon_ready(host, port):
            return {
                "status": "error",
                "message": f"Daemon failed to start within {DAEMON_STARTUP_TIMEOUT} seconds. Check {DAEMON_LOG_FILENAME}",
            }

    payload_dict: Dict[str, Any] = {"cmd": cmd, "args": args}
    if resolved_token:
        payload_dict["token"] = resolved_token
    payload = json.dumps(payload_dict) + "\n"
    res = {"status": "error", "message": "No response from daemon"}
    with socket.create_connection((host, port), timeout=60.0) as s:
        s.sendall(payload.encode("utf-8"))
        buf = bytearray()
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\n" in buf:
                idx = buf.index(b"\n")
                line_bytes = bytes(buf[:idx])
                res = json.loads(line_bytes.decode("utf-8"))
                break

    # 2. Store successful responses into L2 SQLite cache for future instant retrieval
    if is_cacheable and cache_inst is not None and cache_key and res.get("status") == "ok":
        try:
            cache_inst.put(qtype, cache_key, res)
        except Exception as e:
            logger.debug(f"L2 cache store error: {e}")

    if "time_ms" not in res:
        res["time_ms"] = round((time.perf_counter() - t0) * 1000.0, 4)

    return res


def query_oracle(
    cmd: str,
    args: Optional[Dict[str, Any]] = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    token: Optional[str] = None,
    auto_spawn: bool = True,
    l2_cache: Optional[L2SQLiteCache] = None,
) -> Dict[str, Any]:
    """Client helper function to query the Ghidra Oracle daemon with session token support."""
    return client_send_request(
        cmd=cmd,
        args=args or {},
        host=host,
        port=port,
        auto_spawn=auto_spawn,
        l2_cache=l2_cache,
        token=token,
    )


# ==============================================================================
# CLI Pretty Printers
# ==============================================================================

def print_decompile_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    for item in res.get("results", []):
        t = item.get("target")
        va = item.get("va")
        rva = item.get("rva")
        name = item.get("name", "Unknown")
        entry_rva = item.get("entry_rva", rva)
        cached_str = " (L2 CACHED)" if res.get("l2_cached") else (" (CACHED)" if item.get("cached") else "")
        print(f"\n{'='*80}")
        print(f"=== DECOMPILED {t} ({name} @ VA: {va} | RVA: {rva} | Hook RVA: {entry_rva}){cached_str} ===")
        print(f"{'='*80}")
        if "error" in item:
            print(f"ERROR: {item['error']}")
        else:
            print(item.get("code", ""))


def print_vtable_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    vt_va = res.get("vtable_va")
    vt_rva = res.get("vtable_rva")
    cnt = res.get("count")
    cached_str = " (L2 CACHED)" if res.get("l2_cached") else (" (CACHED)" if res.get("cached") else "")
    print(f"\n{'='*85}")
    print(f"=== VTABLE @ {vt_va} (RVA: {vt_rva}) [{cnt} entries]{cached_str} ===")
    print(f"{'='*85}")
    print(f"{'Slot':<6} {'Slot RVA':<12} {'Target VA':<12} {'Runtime Hook RVA':<18} {'Function Name / Symbol'}")
    print(f"{'-'*85}")
    for e in res.get("entries", []):
        slot = f"[{e.get('slot'):2d}]"
        s_rva = e.get("slot_rva", "")
        fn_va = e.get("fn_va", "")
        fn_rva = e.get("fn_rva", "")
        name = e.get("name", "")
        comment = f" ; {e['comment']}" if e.get("comment") else ""
        print(f"{slot:<6} {s_rva:<12} {fn_va:<12} {fn_rva:<18} {name}{comment}")


def print_disasm_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    cnt = res.get("count")
    cached_str = " (L2 CACHED)" if res.get("l2_cached") else ""
    print(f"\n{'='*85}")
    print(f"=== DISASSEMBLY @ {t_va} (RVA: {t_rva}) [{cnt} instructions]{cached_str} ===")
    print(f"{'='*85}")
    print(f"{'VA':<12} {'RVA':<12} {'Hex Bytes':<10} {'Mnemonic':<8} {'Operands'}")
    print(f"{'-'*85}")
    for insn in res.get("instructions", []):
        va = insn.get("va")
        rva = insn.get("rva")
        raw = insn.get("bytes")
        mnem = insn.get("mnemonic")
        ops = insn.get("operands")
        comment = f" ; {insn['comment']}" if insn.get("comment") else ""
        print(f"{va:<12} {rva:<12} {raw:<10} {mnem:<8} {ops}{comment}")


def print_refs_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    tot = res.get("total_refs")
    cached_str = " (L2 CACHED)" if res.get("l2_cached") else ""
    print(f"\n{'='*85}")
    print(f"=== REFERENCES TO {t_va} (RVA: {t_rva}) [{tot} total]{cached_str} ===")
    print(f"{'='*85}")
    for r in res.get("references", []):
        f_va = r.get("from_va")
        f_rva = r.get("from_rva")
        rtype = r.get("ref_type")
        cname = r.get("caller_name")
        c_rva = r.get("caller_entry_rva")
        c_str = f" in {cname} (Hook RVA: {c_rva})" if cname != "None" else ""
        print(f"From {f_va} (RVA: {f_rva}) [{rtype}]{c_str}")


def print_adrp_add_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    sym = res.get("symbol") or "Unknown"
    d_cnt = res.get("direct_refs_count", 0)
    p_cnt = res.get("page_refs_count", 0)
    cached_str = " (L2 CACHED)" if res.get("l2_cached") else ""
    print(f"\n{'='*85}")
    print(f"=== PC-RELATIVE ADRP/ADD REFERENCES FOR {t_va} (RVA: {t_rva} | {sym}){cached_str} ===")
    print(f"Target Page: {res.get('target_page')} | Offset: {res.get('target_offset')} | Direct Xrefs: {d_cnt} | Page Hits: {p_cnt}")
    print(f"{'='*85}")
    if res.get("page_references"):
        print(f"{'Insn VA':<12} {'Insn RVA':<12} {'Reg':<5} {'Paired Insn':<30} {'Caller Function'}")
        print(f"{'-'*85}")
        for p in res.get("page_references", []):
            exact = " [EXACT MATCH]" if p.get("exact_offset_match") else ""
            print(f"{p['insn_va']:<12} {p['insn_rva']:<12} {p['register']:<5} {str(p['paired_insn']):<30} {p['caller']}{exact}")


def print_opcodes_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    min_op = res.get("min")
    max_op = res.get("max")
    cnt = res.get("count")
    tot = res.get("total_indexed_gates")
    cached_str = " (L2 CACHED)" if res.get("l2_cached") else ""
    print(f"\n{'='*85}")
    print(f"=== DISPATCHER OPCODES [Range: {min_op} .. {max_op}] ({cnt} gates matching / {tot} total indexed){cached_str} ===")
    print(f"{'='*85}")
    print(f"{'Opcode':<8} {'Hex':<8} {'Gate VA':<12} {'Gate RVA':<12} {'Instruction':<24} {'Associated Function'}")
    print(f"{'-'*85}")
    for g in res.get("gates", []):
        op = g["opcode"]
        op_h = g["opcode_hex"]
        va = g["va"]
        rva = g["rva"]
        asm = g["asm"]
        fn = g.get("func_name") or "-"
        print(f"{op:<8} {op_h:<8} {va:<12} {rva:<12} {asm:<24} {fn}")


def print_status_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    print(f"\n{'='*75}")
    print("=== GHIDRA ORACLE DAEMON STATUS (127.0.0.1:5073) ===")
    print(f"{'='*75}")
    print(f"Uptime:             {res.get('uptime_human')} ({res.get('uptime_seconds')}s)")
    print(f"Resource Mode:      {res.get('resource_mode', 'balanced')} (Hibernating: {res.get('is_hibernating', False)})")
    print(f"Ghidra Project:     {res.get('project_name')} in {res.get('project_dir')}")
    print(f"Program:            {res.get('program_name')} (Base: {res.get('image_base')})")
    print(f"Functions in DB:    {res.get('function_count'):,}")
    print(f"Indexed Opcode Gates: {res.get('indexed_opcode_gates'):,}")
    print(f"Indexed ADRP Pages: {res.get('indexed_adrp_pages'):,}")
    d_cache = res.get("decompile_cache", {})
    v_cache = res.get("vtable_cache", {})
    print(f"Decompile Cache:    {d_cache.get('size')}/{d_cache.get('capacity')} entries | Hit Rate: {d_cache.get('hit_rate_pct')}% ({d_cache.get('hits')} hits, {d_cache.get('misses')} misses)")
    print(f"VTable Cache:       {v_cache.get('size')}/{v_cache.get('capacity')} entries | Hit Rate: {v_cache.get('hit_rate_pct')}% ({v_cache.get('hits')} hits, {v_cache.get('misses')} misses)")
    print(f"L2 SQLite Cache:    {res.get('l2_cache_count', 0)} entries")
    print(f"Overall Hit Rate:   {res.get('overall_hit_rate_pct')}%")
    print(f"Write-Overlay:      {res.get('overlay_renames_count')} renames, {res.get('overlay_comments_count')} comments")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ghidra Oracle: Dual-mode Persistent TCP/JSON Daemon & CLI Client",
        add_help=False,
    )
    parser.add_argument("command", nargs="?", default="status", help="Command to run")
    parser.add_argument("args", nargs="*", help="Command arguments")
    parser.add_argument("--host", default=DEFAULT_HOST, help="TCP daemon host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP daemon port (default 5073)")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow binding daemon to non-loopback network addresses",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Session token for daemon authentication",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON response")
    parser.add_argument("--project-dir", default=None, help="Custom Ghidra project directory")
    parser.add_argument("--project-name", default=None, help="Custom Ghidra project name")
    parser.add_argument("--program-name", default=None, help="Custom program name inside project")
    parser.add_argument(
        "--mode",
        choices=["eco", "balanced", "turbo", "auto"],
        default=None,
        help="Governor resource mode (eco, balanced, turbo, auto)",
    )
    parser.add_argument(
        "--style",
        choices=["firstpass", "register", "jumptable", "paramid", "normalize", "decompile"],
        default=None,
        help="Decompiler simplification style (firstpass, register, jumptable, paramid, normalize, decompile)",
    )
    parser.add_argument(
        "--throttle-ms",
        type=int,
        default=None,
        help="Duty-cycle throttle delay in milliseconds between decompilations",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clears persistent L2 SQLite cache and exits",
    )
    parser.add_argument(
        "--clean-stale-locks",
        action="store_true",
        help="Allow deletion of stale lock files older than threshold",
    )
    parser.add_argument(
        "--lock-stale-threshold-sec",
        type=float,
        default=600.0,
        help="Threshold in seconds before a lock file is considered stale (default 600s)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run daemon in mock/standalone mode with synthetic responses (no Ghidra/JDK installation required)",
    )
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")

    parsed, unknown = parser.parse_known_args()

    if parsed.help or not parsed.command:
        print(__doc__)
        parser.print_help()
        return

    cmd = parsed.command.lower()
    c_args = parsed.args

    # Handle clear-cache subcommand or --clear-cache flag early
    if parsed.clear_cache or cmd == "clear-cache":
        cache = get_client_l2_cache()
        cache.clear()
        print(f"[*] Persistent L2 SQLite cache cleared successfully ({cache.db_path}).")
        return

    # 1. Daemon serve mode
    if cmd == "serve":
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        target_mode = parsed.mode or "balanced"
        use_mock = parsed.mock or (os.environ.get("SUPERGHIDRA_MOCK_ORACLE") == "1")
        if not use_mock:
            try:
                import pyghidra  # noqa: F401
            except ImportError:
                print("[!] PyGhidra not detected. Running daemon in mock standalone mode (--mock).")
                use_mock = True

        if use_mock:
            session = MockGhidraOracleSession(resource_mode=target_mode)
            print(f"[*] Initializing Mock Ghidra Oracle (Mode: {session.resource_mode}, Zero-JVM standalone)...")
        else:
            session = GhidraOracleSession(
                project_dir=parsed.project_dir,
                project_name=parsed.project_name,
                program_name=parsed.program_name,
                resource_mode=target_mode,
                clean_stale_locks=parsed.clean_stale_locks,
                lock_stale_threshold_sec=parsed.lock_stale_threshold_sec,
            )
            if parsed.mode:
                session.set_resource_mode(parsed.mode)
            print(f"[*] Initializing Ghidra & OpenJDK 21 (Mode: {session.resource_mode})...")
            session.initialize()
        # Resolve or generate session token
        token = parsed.token or os.environ.get(SUPERGHIDRA_TOKEN_ENV)
        if not token:
            token = secrets.token_hex(24)
        token_path = save_session_token(token)
        print(f"[*] Session token active and stored in {token_path}")

        server = GhidraDaemonServer(
            session,
            host=parsed.host,
            port=parsed.port,
            allow_remote=parsed.allow_remote,
            token=token,
        )
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n[*] Stopping Ghidra Oracle daemon...")
            server.stop()
        return

    # 2. Client Commands
    req_args = {}
    if cmd == "rva":
        if not c_args:
            print("Usage: python ghidra_oracle.py rva <addr>")
            return
        req_args["addr"] = c_args[0]
    elif cmd == "decompile":
        if not c_args:
            print("Usage: python ghidra_oracle.py decompile <addr...>")
            return
        req_args["targets"] = c_args
        if parsed.style:
            req_args["style"] = parsed.style
        if parsed.throttle_ms is not None:
            req_args["throttle_ms"] = parsed.throttle_ms
    elif cmd == "vtable":
        if not c_args:
            print("Usage: python ghidra_oracle.py vtable <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 12
    elif cmd == "disassemble":
        if not c_args:
            print("Usage: python ghidra_oracle.py disassemble <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 30
    elif cmd in ("refs", "references"):
        if not c_args:
            print("Usage: python ghidra_oracle.py refs <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 20
    elif cmd == "adrp_add":
        if not c_args:
            print("Usage: python ghidra_oracle.py adrp_add <symbol_or_addr>")
            return
        req_args["target"] = c_args[0]
    elif cmd == "opcodes":
        min_op = int(c_args[0]) if len(c_args) > 0 else 500
        max_op = int(c_args[1]) if len(c_args) > 1 else 550
        req_args["min"] = min_op
        req_args["max"] = max_op
    elif cmd == "rename":
        if len(c_args) < 2:
            print("Usage: python ghidra_oracle.py rename <addr> <name>")
            return
        req_args["addr"] = c_args[0]
        req_args["name"] = c_args[1]
    elif cmd == "comment":
        if len(c_args) < 2:
            print("Usage: python ghidra_oracle.py comment <addr> <text>")
            return
        req_args["addr"] = c_args[0]
        req_args["comment"] = " ".join(c_args[1:])
    elif cmd == "overlay":
        req_args["action"] = c_args[0] if c_args else "list"
    elif cmd == "type":
        if not c_args:
            print("Usage: python ghidra_oracle.py type <name_or_id>")
            return
        req_args["name"] = c_args[0]
    elif cmd == "register_struct":
        if len(c_args) < 2:
            print("Usage: python ghidra_oracle.py register_struct <name> <byte_size> [members_json]")
            return
        req_args["name"] = c_args[0]
        req_args["byte_size"] = int(c_args[1])
        req_args["members"] = json.loads(c_args[2]) if len(c_args) > 2 else []
    elif cmd == "hibernate":
        pass
    elif cmd == "mode":
        target_mode = None
        if c_args:
            target_mode = c_args[0].lower()
        elif parsed.mode:
            target_mode = parsed.mode.lower()
        else:
            print("Usage: python ghidra_oracle.py mode <eco|balanced|turbo|auto>")
            return
        if target_mode not in ("eco", "balanced", "turbo", "auto"):
            print(f"ERROR: Invalid mode '{target_mode}'. Choose from: eco, balanced, turbo, auto")
            return
        req_args["mode"] = target_mode
    elif cmd in ("status", "stop", "ping"):
        pass
    else:
        print(f"Unknown command: {cmd}")
        print("Available commands: decompile, vtable, disassemble, refs, adrp_add, opcodes, rva, rename, comment, overlay, type, register_struct, status, stop, hibernate, mode, clear-cache, serve")
        return

    res = client_send_request(
        cmd,
        req_args,
        host=parsed.host,
        port=parsed.port,
        token=parsed.token,
    )

    if parsed.json:
        print(json.dumps(res, indent=2))
        return

    # Human-readable output formatting
    if cmd == "rva":
        if res.get("status") == "ok":
            va = res.get("va")
            rva = res.get("rva")
            t_ms = res.get("time_ms", 0.0)
            print(f"VA:     {va}  (Ghidra Virtual Address)")
            print(f"RVA:    {rva}  (Runtime Relative Virtual Address, -0x100000)")
            print(f"Lookup: {t_ms:.4f} ms")
        else:
            print(f"ERROR: {res.get('message')}")
    elif cmd == "decompile":
        print_decompile_result(res)
    elif cmd == "vtable":
        print_vtable_result(res)
    elif cmd == "disassemble":
        print_disasm_result(res)
    elif cmd in ("refs", "references"):
        print_refs_result(res)
    elif cmd == "adrp_add":
        print_adrp_add_result(res)
    elif cmd == "opcodes":
        print_opcodes_result(res)
    elif cmd == "status":
        print_status_result(res)
    elif cmd in ("rename", "comment", "stop", "ping", "hibernate", "mode"):
        print(res.get("message") or res)
    elif cmd == "overlay":
        print(json.dumps(res.get("overlay", res), indent=2))
    elif cmd == "type":
        if res.get("status") == "ok":
            print(f"=== Type: {res.get('type', {}).get('name', 'Unknown')} ===")
            print(res.get("c_decl", ""))
        else:
            print(f"ERROR: {res.get('message')}")
    elif cmd == "register_struct":
        if res.get("status") == "ok":
            print(f"[*] Registered struct '{res.get('name')}' (ID: {res.get('type_id')}, Size: {res.get('byte_size')}B)")
            print(res.get("c_decl", ""))
        else:
            print(f"ERROR: {res.get('message')}")

    if res.get("l2_cached") and cmd not in ("rva", "status"):
        t_ms = res.get("time_ms", 0.0)
        print(f"\n[L2 SQLite Cache Hit: {t_ms:.4f} ms | 0% JVM CPU]")


if __name__ == "__main__":
    main()
