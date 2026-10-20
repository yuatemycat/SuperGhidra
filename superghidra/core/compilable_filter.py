"""
Compilable Decompiler Filter and C Idiom Normalizer.
References: U1, U2, U3 in docs/SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md

Transforms Ghidra's raw decompiler pseudo-C AST into compilable, standard C99/C++17 code:
1. Rewrites Ghidra synthetic scalar types (undefined*, ulonglong, etc.) into <stdint.h> types.
2. Expands Ghidra synthetic macro intrinsics (CONCAT44, SUB84, ZEXT48, SEXT48) into standard C bitwise expressions.
3. Cleans compiler idioms (stack canaries, in_FS_OFFSET, extraout_*, __stack_chk_fail).
4. Cleans calling convention warning comments and demangles signatures.
5. Injects standard headers (#include <stdint.h>, <stdbool.h>, <stddef.h>).
"""

from __future__ import annotations

import re
from typing import Optional


# Scalar type mapping: Ghidra pseudo-types -> standard C99 types
GHIDRA_TYPE_MAP = [
    (r"\bundefined8\b", "uint64_t"),
    (r"\blonglong\b", "int64_t"),
    (r"\bulonglong\b", "uint64_t"),
    (r"\bundefined4\b", "uint32_t"),
    (r"\buint\b", "uint32_t"),
    (r"\bulong\b", "uint32_t"),
    (r"\bundefined2\b", "uint16_t"),
    (r"\bushort\b", "uint16_t"),
    (r"\bundefined1\b", "uint8_t"),
    (r"\buchar\b", "uint8_t"),
    (r"\bbyte\b", "uint8_t"),
    (r"\b__int32_t\b", "int32_t"),
    (r"\bint1\b", "int8_t"),
    (r"\bint2\b", "int16_t"),
    (r"\bint4\b", "int32_t"),
    (r"\bint8\b", "int8_t"),
    (r"\bint16\b", "int16_t"),
    (r"\bint32\b", "int32_t"),
    (r"\bint64\b", "int64_t"),
    (r"\buint8\b", "uint8_t"),
    (r"\buint16\b", "uint16_t"),
    (r"\buint32\b", "uint32_t"),
    (r"\buint64\b", "uint64_t"),
    (r"\bpointer\b", "void*"),
]

STANDARD_HEADERS = (
    "#include <stdint.h>\n"
    "#include <stdbool.h>\n"
    "#include <stddef.h>\n"
)


class CompilableDecompilerFilter:
    """
    Normalizes Ghidra pseudo-C into standard compilable C source code.
    """

    @classmethod
    def rewrite_types(cls, code: str) -> str:
        """Translates Ghidra scalar types into stdint types."""
        result = code
        for pattern, replacement in GHIDRA_TYPE_MAP:
            result = re.sub(pattern, replacement, result)
        return result

    @classmethod
    def expand_intrinsics(cls, code: str) -> str:
        """
        Expands Ghidra synthetic macro intrinsics into standard C bitwise expressions.
        """
        # Helper to parse 2-arg intrinsics with balanced parentheses
        def _expand_macro(text: str, name: str, expander) -> str:
            pattern = re.compile(rf"\b{name}\s*\(")
            while True:
                match = pattern.search(text)
                if not match:
                    break
                start = match.end()
                # Parse matching arguments considering parenthesis nesting
                depth = 1
                i = start
                args = []
                current_arg = []
                while i < len(text) and depth > 0:
                    ch = text[i]
                    if ch == '(':
                        depth += 1
                        current_arg.append(ch)
                    elif ch == ')':
                        depth -= 1
                        if depth == 0:
                            args.append("".join(current_arg).strip())
                            break
                        else:
                            current_arg.append(ch)
                    elif ch == ',' and depth == 1:
                        args.append("".join(current_arg).strip())
                        current_arg = []
                    else:
                        current_arg.append(ch)
                    i += 1
                if depth == 0:
                    replacement = expander(args)
                    text = text[:match.start()] + replacement + text[i+1:]
                else:
                    break
            return text

        # 1. CONCAT44(hi, lo) -> (((uint64_t)(hi) << 32) | (uint32_t)(lo))
        code = _expand_macro(code, "CONCAT44", lambda args: f"(((uint64_t)({args[0]}) << 32) | (uint32_t)({args[1]}))" if len(args) == 2 else f"CONCAT44({','.join(args)})")

        # 2. CONCAT22(hi, lo) -> (((uint32_t)(hi) << 16) | (uint16_t)(lo))
        code = _expand_macro(code, "CONCAT22", lambda args: f"(((uint32_t)({args[0]}) << 16) | (uint16_t)({args[1]}))" if len(args) == 2 else f"CONCAT22({','.join(args)})")

        # 3. CONCAT11(hi, lo) -> (((uint16_t)(hi) << 8) | (uint8_t)(lo))
        code = _expand_macro(code, "CONCAT11", lambda args: f"(((uint16_t)({args[0]}) << 8) | (uint8_t)({args[1]}))" if len(args) == 2 else f"CONCAT11({','.join(args)})")

        # 4. SUB84(val, off) -> ((uint32_t)((val) >> ((off) * 8)))
        code = _expand_macro(code, "SUB84", lambda args: f"((uint32_t)(({args[0]}) >> (({args[1]}) * 8)))" if len(args) == 2 else f"SUB84({','.join(args)})")

        # 5. SUB42(val, off) -> ((uint16_t)((val) >> ((off) * 8)))
        code = _expand_macro(code, "SUB42", lambda args: f"((uint16_t)(({args[0]}) >> (({args[1]}) * 8)))" if len(args) == 2 else f"SUB42({','.join(args)})")

        # 6. SUB41(val, off) -> ((uint8_t)((val) >> ((off) * 8)))
        code = _expand_macro(code, "SUB41", lambda args: f"((uint8_t)(({args[0]}) >> (({args[1]}) * 8)))" if len(args) == 2 else f"SUB41({','.join(args)})")

        # 7. ZEXT48(val) -> ((uint64_t)(uint32_t)(val))
        code = _expand_macro(code, "ZEXT48", lambda args: f"((uint64_t)(uint32_t)({args[0]}))" if len(args) == 1 else f"ZEXT48({','.join(args)})")

        # 8. SEXT48(val) -> ((int64_t)(int32_t)({val}))
        code = _expand_macro(code, "SEXT48", lambda args: f"((int64_t)(int32_t)({args[0]}))" if len(args) == 1 else f"SEXT48({','.join(args)})")

        return code

    @classmethod
    def cleanup_canaries_and_idioms(cls, code: str) -> str:
        """
        Removes stack canary checks and compiler artifacts.
        """
        # 1. Strip in_FS_OFFSET declarations
        code = re.sub(r"^\s*(?:[a-zA-Z0-9_*]+\s+)+in_FS_OFFSET\s*;\s*\n?", "", code, flags=re.MULTILINE)

        # 2. Strip canary initialization: [type] var = *(type *)(in_FS_OFFSET + 0x28);
        code = re.sub(r"^\s*(?:[a-zA-Z0-9_*]+\s+)*\w+\s*=\s*\*\(.*?\)\s*\(\s*in_FS_OFFSET\s*\+\s*0x28\s*\)\s*;\s*\n?", "", code, flags=re.MULTILINE)

        # 3. Success-side canary: the real return sits inside the check, and
        # __stack_chk_fail() follows the closing brace. Keep that return.
        # The failure-side form (check body is the fail call) is removed below.
        code = re.sub(
            r"if\s*\([^;{}]*in_FS_OFFSET[^;{}]*\)\s*\{\s*"
            r"(return\b[^;]*;)\s*\}\s*"
            r"(?:/\*[^*]*\*/\s*)?"
            r"__stack_chk_fail\s*\(\s*\)\s*;",
            r"\1",
            code,
            flags=re.MULTILINE,
        )

        # 4. Strip canary check blocks: if (...) { ... __stack_chk_fail(); ... }
        code = re.sub(
            r"if\s*\([^;{}]*in_FS_OFFSET[^;{}]*\)\s*\{[^{}]*__stack_chk_fail\(\)\s*;[^{}]*\}\s*\n?",
            "",
            code,
            flags=re.MULTILINE | re.DOTALL,
        )
        code = re.sub(
            r"if\s*\([^;{}]*in_FS_OFFSET[^;{}]*\)\s*__stack_chk_fail\(\)\s*;\s*\n?",
            "",
            code,
            flags=re.MULTILINE | re.DOTALL,
        )
        code = re.sub(
            r"if\s*\([^;{}]*__stack_chk_fail\(\)[^;{}]*\)\s*;\s*\n?",
            "",
            code,
            flags=re.MULTILINE | re.DOTALL,
        )

        # 4. Fallback cleanup: strip any remaining isolated line containing in_FS_OFFSET or __stack_chk_fail
        code = re.sub(r"^.*?(?:in_FS_OFFSET|__stack_chk_fail).*?$\n?", "", code, flags=re.MULTILINE)

        # 4. Strip extraout_* and in_register_* artifacts
        code = re.sub(r"\bextraout_\w+\b", "0", code)
        code = re.sub(r"\bin_register_\w+\b", "0", code)

        # 5. Clean Ghidra warning comments
        code = re.sub(r"/\*\s*WARNING:[^*]*\*/\s*", "", code)

        return code

    @classmethod
    def glibc_ctype_support(cls, code: str) -> str:
        """Define glibc ctype helpers when the decompiler emitted them.

        MinGW has no ``__ctype_b_loc``. The tables use glibc's little-endian
        class bits and are indexed from -128, which is what those calls do.
        Samples that never mention the helpers are left unchanged.
        """
        want_b = "__ctype_b_loc" in code
        want_lower = "__ctype_tolower_loc" in code
        want_upper = "__ctype_toupper_loc" in code
        if not (want_b or want_lower or want_upper):
            return code
        parts = [
            "static unsigned short sg_b_table[384];",
            "static unsigned short *sg_b_mid;",
            "static int sg_tol_table[384];",
            "static int *sg_tol_mid;",
            "static int sg_tou_table[384];",
            "static int *sg_tou_mid;",
            "static int sg_ctype_ready;",
            "static void sg_ctype_init(void) {",
            "  int c;",
            "  if (sg_ctype_ready) return;",
            "  sg_ctype_ready = 1;",
            "  for (c = -128; c <= 255; c++) {",
            "    unsigned short bits = 0;",
            "    int lower = c;",
            "    int upper = c;",
            "    if (c >= 0 && c <= 255) {",
            "      if (c >= 'A' && c <= 'Z') { bits = (unsigned short)(bits | 0x100u); lower = c + 32; }",
            "      if (c >= 'a' && c <= 'z') { bits = (unsigned short)(bits | 0x200u); upper = c - 32; }",
            "      if ((bits & 0x300u) != 0) bits = (unsigned short)(bits | 0x400u);",
            "      if (c >= '0' && c <= '9') bits = (unsigned short)(bits | 0x800u);",
            "      if ((bits & 0x800u) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) bits = (unsigned short)(bits | 0x1000u);",
            "      if (c == ' ' || c == '\\t' || c == '\\n' || c == '\\v' || c == '\\f' || c == '\\r') bits = (unsigned short)(bits | 0x2000u);",
            "      if (c == ' ' || c == '\\t') bits = (unsigned short)(bits | 0x0001u);",
            "      if (c > 0x20 && c < 0x7f) bits = (unsigned short)(bits | 0x8000u);",
            "      if ((bits & 0x8000u) || c == ' ') bits = (unsigned short)(bits | 0x4000u);",
            "      if (c < 0x20 || c == 0x7f) bits = (unsigned short)(bits | 0x0002u);",
            "      if ((bits & 0x8000u) && (bits & 0xc00u) == 0) bits = (unsigned short)(bits | 0x0004u);",
            "      if ((bits & 0xc00u) != 0) bits = (unsigned short)(bits | 0x0008u);",
            "    }",
            "    sg_b_table[c + 128] = bits;",
            "    sg_tol_table[c + 128] = lower;",
            "    sg_tou_table[c + 128] = upper;",
            "  }",
            "  sg_b_mid = sg_b_table + 128;",
            "  sg_tol_mid = sg_tol_table + 128;",
            "  sg_tou_mid = sg_tou_table + 128;",
            "}",
        ]
        if want_b:
            parts.append(
                "static unsigned short **__ctype_b_loc(void) { sg_ctype_init(); return &sg_b_mid; }"
            )
        if want_lower:
            parts.append(
                "static int **__ctype_tolower_loc(void) { sg_ctype_init(); return &sg_tol_mid; }"
            )
        if want_upper:
            parts.append(
                "static int **__ctype_toupper_loc(void) { sg_ctype_init(); return &sg_tou_mid; }"
            )
        shim = "\n".join(parts) + "\n"
        return shim + code

    @classmethod
    def filter(
        cls,
        code: str,
        emit_compilable: bool = True,
        strip_canary: bool = True,
        include_headers: bool = True,
    ) -> str:
        """
        Applies full pipeline of compilable transformations.
        """
        if not code or not emit_compilable:
            return code

        result = cls.rewrite_types(code)
        result = cls.expand_intrinsics(result)

        if strip_canary:
            result = cls.cleanup_canaries_and_idioms(result)

        result = cls.glibc_ctype_support(result)

        if include_headers and "#include <stdint.h>" not in result:
            result = f"{STANDARD_HEADERS}\n{result.lstrip()}"

        return result
