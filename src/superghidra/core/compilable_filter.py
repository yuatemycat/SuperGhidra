"""
Compilable Decompiler Filter and C Idiom Normalizer.
References: U1, U2, U3 in docs/SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md

Transforms Ghidra's raw decompiler pseudo-C AST and Hex-Rays IDA Pro pseudo-C
into compilable, standard C99/C++17 code:
1. Rewrites Ghidra synthetic scalar types (undefined*, ulonglong, etc.) into <stdint.h> types.
2. Expands Ghidra synthetic macro intrinsics (CONCAT44, SUB84, ZEXT48, SEXT48) into standard C bitwise expressions.
3. Cleans compiler idioms (stack canaries, in_FS_OFFSET, extraout_*, __stack_chk_fail).
4. Cleans calling convention warning comments and demangles signatures.
5. Provides a clean-room Hex-Rays defs.h compatibility header (IDA_COMPAT_DEFS_H) and normalizes IDA idioms.
6. Injects standard headers (#include <stdint.h>, <stdbool.h>, <stddef.h>).
"""

from __future__ import annotations

import re
from typing import Any

# Scalar type mapping: Ghidra pseudo-types -> standard C99 types
GHIDRA_TYPE_MAP = [
    (r"\bundefined8\b", "uint64_t"),
    (r"\blonglong\b", "int64_t"),
    (r"\bulonglong\b", "uint64_t"),
    (r"\bundefined4\b", "uint32_t"),
    (r"\buint\b", "uint32_t"),
    (r"\bulong\b", "unsigned long"),
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

# Clean-room C99/C++17 compatibility header for Hex-Rays IDA Pro pseudo-C emissions.
IDA_COMPAT_DEFS_H = """#ifndef SUPERGHIDRA_IDA_COMPAT_DEFS_H
#define SUPERGHIDRA_IDA_COMPAT_DEFS_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef uint8_t _BYTE;
typedef uint16_t _WORD;
typedef uint32_t _DWORD;
typedef uint64_t _QWORD;
#if defined(__SIZEOF_INT128__)
typedef __uint128_t _OWORD;
#else
typedef struct { uint64_t lo; uint64_t hi; } _OWORD;
#endif
typedef int8_t _BOOL1;
typedef int16_t _BOOL2;
typedef int32_t _BOOL4;
typedef int64_t _BOOL8;
typedef uint8_t _UNKNOWN;

#if !defined(_MSC_VER) && !defined(__MINGW32__)
#ifndef __int8
typedef int8_t __int8;
#endif
#ifndef __int16
typedef int16_t __int16;
#endif
#ifndef __int32
typedef int32_t __int32;
#endif
#ifndef __int64
typedef int64_t __int64;
#endif
#ifndef __fastcall
#define __fastcall
#endif
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __thiscall
#define __thiscall
#endif
#endif

#ifndef LOBYTE
#define LOBYTE(x) ((_BYTE)((uint64_t)(x) & 0xFFU))
#endif
#ifndef HIBYTE
#define HIBYTE(x) ((_BYTE)(((uint64_t)(x) >> 8) & 0xFFU))
#endif
#ifndef LOWORD
#define LOWORD(x) ((_WORD)((uint64_t)(x) & 0xFFFFU))
#endif
#ifndef HIWORD
#define HIWORD(x) ((_WORD)(((uint64_t)(x) >> 16) & 0xFFFFU))
#endif
#ifndef LODWORD
#define LODWORD(x) ((_DWORD)((uint64_t)(x) & 0xFFFFFFFFULL))
#endif
#ifndef HIDWORD
#define HIDWORD(x) ((_DWORD)(((uint64_t)(x) >> 32) & 0xFFFFFFFFULL))
#endif

#define BYTE1(x) ((_BYTE)(((uint64_t)(x) >> 8) & 0xFFU))
#define BYTE2(x) ((_BYTE)(((uint64_t)(x) >> 16) & 0xFFU))
#define BYTE3(x) ((_BYTE)(((uint64_t)(x) >> 24) & 0xFFU))
#define BYTE4(x) ((_BYTE)(((uint64_t)(x) >> 32) & 0xFFU))
#define BYTE5(x) ((_BYTE)(((uint64_t)(x) >> 40) & 0xFFU))
#define BYTE6(x) ((_BYTE)(((uint64_t)(x) >> 48) & 0xFFU))
#define BYTE7(x) ((_BYTE)(((uint64_t)(x) >> 56) & 0xFFU))

#define WORD1(x) ((_WORD)(((uint64_t)(x) >> 16) & 0xFFFFU))
#define WORD2(x) ((_WORD)(((uint64_t)(x) >> 32) & 0xFFFFU))
#define WORD3(x) ((_WORD)(((uint64_t)(x) >> 48) & 0xFFFFU))

#define DWORD1(x) ((_DWORD)(((uint64_t)(x) >> 32) & 0xFFFFFFFFULL))
#define DWORD2(x) (*((_DWORD *)&(x) + 2))

#define SLOBYTE(x) ((int8_t)((uint64_t)(x) & 0xFFU))
#define SHIBYTE(x) ((int8_t)(((uint64_t)(x) >> 8) & 0xFFU))
#define SLOWORD(x) ((int16_t)((uint64_t)(x) & 0xFFFFU))
#define SHIWORD(x) ((int16_t)(((uint64_t)(x) >> 16) & 0xFFFFU))
#define SLODWORD(x) ((int32_t)((uint64_t)(x) & 0xFFFFFFFFULL))
#define SHIDWORD(x) ((int32_t)(((uint64_t)(x) >> 32) & 0xFFFFFFFFULL))

#define __PAIR16__(high, low) ((((uint16_t)(high)) << 8) | (uint8_t)(low))
#define __PAIR32__(high, low) ((((uint32_t)(high)) << 16) | (uint16_t)(low))
#define __PAIR64__(high, low) ((((uint64_t)(high)) << 32) | (uint32_t)(low))

static inline float _sg_coerce_float(uint32_t v) {
    union { uint32_t u; float f; } u;
    u.u = v;
    return u.f;
}
static inline double _sg_coerce_double(uint64_t v) {
    union { uint64_t u; double d; } u;
    u.u = v;
    return u.d;
}
static inline uint32_t _sg_coerce_uint32(float f) {
    union { float f; uint32_t u; } u;
    u.f = f;
    return u.u;
}
static inline uint64_t _sg_coerce_uint64(double d) {
    union { double d; uint64_t u; } u;
    u.d = d;
    return u.u;
}

#define COERCE_FLOAT(v) _sg_coerce_float((uint32_t)(v))
#define COERCE_DOUBLE(v) _sg_coerce_double((uint64_t)(v))
#define COERCE_UNSIGNED_INT(v) _sg_coerce_uint32((float)(v))
#define COERCE_UNSIGNED_INT64(v) _sg_coerce_uint64((double)(v))

static inline int _sg_parity8(uint8_t v) {
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (~v) & 1;
}

#define __CFADD__(x, y) (sizeof(x) <= 4 ? ((uint32_t)(x) > (uint32_t)((uint32_t)(x) + (uint32_t)(y))) : ((uint64_t)(x) > (uint64_t)((uint64_t)(x) + (uint64_t)(y))))
#define __OFSUB__(x, y) (sizeof(x) <= 4 ? ((((int32_t)(x) ^ (int32_t)(y)) < 0) && (((int32_t)(x) ^ (int32_t)((uint32_t)(x) - (uint32_t)(y))) < 0)) : ((((int64_t)(x) ^ (int64_t)(y)) < 0) && (((int64_t)(x) ^ (int64_t)((uint64_t)(x) - (uint64_t)(y))) < 0)))
#define __SETP__(x, y) _sg_parity8((uint8_t)((uint64_t)(x) - (uint64_t)(y)))
#endif /* SUPERGHIDRA_IDA_COMPAT_DEFS_H */
"""

_IDA_LVALUE_MACRO_MAP = {
    "LOBYTE": ("_BYTE", 0),
    "HIBYTE": ("_BYTE", 1),
    "BYTE1": ("_BYTE", 1),
    "BYTE2": ("_BYTE", 2),
    "BYTE3": ("_BYTE", 3),
    "BYTE4": ("_BYTE", 4),
    "BYTE5": ("_BYTE", 5),
    "BYTE6": ("_BYTE", 6),
    "BYTE7": ("_BYTE", 7),
    "LOWORD": ("_WORD", 0),
    "HIWORD": ("_WORD", 1),
    "WORD1": ("_WORD", 1),
    "WORD2": ("_WORD", 2),
    "WORD3": ("_WORD", 3),
    "LODWORD": ("_DWORD", 0),
    "HIDWORD": ("_DWORD", 1),
    "DWORD1": ("_DWORD", 1),
    "DWORD2": ("_DWORD", 2),
    "SLOBYTE": ("int8_t", 0),
    "SHIBYTE": ("int8_t", 1),
    "SLOWORD": ("int16_t", 0),
    "SHIWORD": ("int16_t", 1),
    "SLODWORD": ("int32_t", 0),
    "SHIDWORD": ("int32_t", 1),
}

_IDA_TOKEN_RE = re.compile(
    r"\b(?:_BYTE|_WORD|_DWORD|_QWORD|_OWORD|_BOOL[1248]|__int(?:8|16|32|64)|_UNKNOWN|"
    r"LOBYTE|HIBYTE|LOWORD|HIWORD|LODWORD|HIDWORD|BYTE[1-7]|WORD[1-3]|DWORD[12]|"
    r"SLOBYTE|SHIBYTE|SLOWORD|SHIWORD|SLODWORD|SHIDWORD|__PAIR(?:16|32|64)__|"
    r"COERCE_FLOAT|COERCE_DOUBLE|COERCE_UNSIGNED_INT|COERCE_UNSIGNED_INT64|"
    r"__CFADD__|__OFSUB__|__SETP__)\b"
)


class CompilableDecompilerFilter:
    """
    Normalizes Ghidra and IDA Pro pseudo-C into standard compilable C source code.
    """

    @classmethod
    def rewrite_types(cls, code: str) -> str:
        """Translates Ghidra scalar types into stdint types."""
        result = code
        for pattern, replacement in GHIDRA_TYPE_MAP:
            result = re.sub(pattern, replacement, result)
        return result

    @classmethod
    def normalize_ida_idioms(cls, code: str) -> str:
        """
        Strips Hex-Rays IDA Pro calling convention/register annotations and
        rewrites lvalue byte/word/dword extraction assignments into pointer casts.
        """
        # 1. Strip IDA separator banners: //----- (0000000000401120) ----
        code = re.sub(
            r"^\s*//-{3,}\s*\([0-9A-Fa-f]+\)\s*-+.*?\n?",
            "",
            code,
            flags=re.MULTILINE,
        )

        # 2. Strip __spoils<...> annotations
        code = re.sub(r"\b__spoils\s*<[^>]*>\s*", "", code)

        # 3. Strip @<register> location annotations (used with __usercall / __userpurge)
        code = re.sub(r"@\s*<[a-zA-Z0-9_:]+>", "", code)

        # 4. Strip IDA calling convention specifiers
        code = re.sub(
            r"\b(?:__fastcall|__usercall|__userpurge|__cdecl|__stdcall|__thiscall|__vectorcall|__noreturn)\b\s*",
            "",
            code,
        )

        # 5. Rewrite lvalue macro assignments: MACRO(lhs) = -> (*((type *)&(lhs) + idx)) =
        def _repl_lvalue_macro(m: re.Match) -> str:
            macro = m.group(1)
            arg = m.group(2).strip()
            ctype, idx = _IDA_LVALUE_MACRO_MAP[macro]
            return f"(*(({ctype} *)&({arg}) + {idx})) "

        macro_names = "|".join(_IDA_LVALUE_MACRO_MAP.keys())
        code = re.sub(
            rf"\b({macro_names})\s*\(([^()]+)\)\s*(?==[^=])",
            _repl_lvalue_macro,
            code,
        )
        return code

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
            "#if defined(_WIN32) || defined(__MINGW32__)",
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
        parts.append("#endif /* _WIN32 || __MINGW32__ */")
        shim = "\n".join(parts) + "\n"
        return shim + code

    @classmethod
    def collapse_pointer_strides(cls, code: str) -> str:
        """
        Roadmap U20: Collapses raw pointer-stride arithmetic into high-level array accesses.
        Transforms:
          - *(type *)(base + index * stride) -> ((type *)(base))[index] (or base[index])
          - *(type *)(base + (index << shift)) -> ((type *)(base))[index]
          - *(_QWORD *)(*(_QWORD *)(base + 0x18) + (longlong)i * 8) -> base->field_18[i]
        """
        # 1. Nested double dereference:
        # *(_QWORD *)(*(_QWORD *)(base + 0xOffset) + (cast)index * 8)
        # -> base->field_Offset[index]
        def _repl_nested_struct_array(m: re.Match) -> str:
            cast1 = m.group(1)
            cast2 = m.group(2)
            base = m.group(3).strip()
            offset = m.group(4).strip()
            idx = m.group(5).strip()
            stride = m.group(6).strip()
            clean_off = offset.replace("0x", "")
            return f"{base}->field_{clean_off}[{idx}]"

        code = re.sub(
            r"\*\s*\(\s*([a-zA-Z0-9_*]+)\s*\*\s*\)\s*\(\s*\*\s*\(\s*([a-zA-Z0-9_*]+)\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\)\s*\+\s*(?:\([a-zA-Z0-9_*]+\)\s*)?([a-zA-Z0-9_]+)\s*\*\s*([0-9]+)\s*\)",
            _repl_nested_struct_array,
            code,
        )

        # 2. Shifted index pointer stride:
        # *(type *)(base + (index << shift)) -> ((type *)(base))[index]
        def _repl_shifted_stride(m: re.Match) -> str:
            type_cast = m.group(1).strip()
            base = m.group(2).strip()
            idx = m.group(3).strip()
            # If base is a clean identifier without casts
            if re.fullmatch(r"[a-zA-Z0-9_]+", base):
                return f"{base}[{idx}]"
            return f"(({type_cast}){base})[{idx}]"

        code = re.sub(
            r"\*\s*\(\s*([a-zA-Z0-9_*]+)\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*\(\s*([a-zA-Z0-9_]+)\s*<<\s*[1-4]\s*\)\s*\)",
            _repl_shifted_stride,
            code,
        )

        # 3. Scaled multiplication pointer stride:
        # *(type *)(base + index * stride) or *(type *)(base + (cast)index * stride)
        def _repl_mult_stride(m: re.Match) -> str:
            type_cast = m.group(1).strip()
            base = m.group(2).strip()
            idx = m.group(3).strip()
            stride = int(m.group(4))
            if re.fullmatch(r"[a-zA-Z0-9_]+", base):
                return f"{base}[{idx}]"
            return f"(({type_cast}){base})[{idx}]"

        code = re.sub(
            r"\*\s*\(\s*([a-zA-Z0-9_*]+)\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*(?:\([a-zA-Z0-9_*]+\)\s*)?([a-zA-Z0-9_]+)\s*\*\s*([0-9]+)\s*\)",
            _repl_mult_stride,
            code,
        )

        # 4. Simple pointer dereference: *(type *)(base + index) -> base[index]
        code = re.sub(
            r"\*\s*\(\s*([a-zA-Z0-9_*]+)\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*\)",
            r"\2[\3]",
            code,
        )

        return code

    @classmethod
    def resolve_callee_types(cls, code: str, struct_catalog: dict | None = None) -> str:
        """
        Auto-resolves callee argument types using STRUCT_CATALOG and standard APIs.
        Replaces generic undefined8/longlong arguments with typed pointers when callee is known.
        """
        # Standard Win32/POSIX Callee Signatures mapping:
        KNOWN_CALLEES = {
            "VirtualAlloc": "LPVOID VirtualAlloc(LPVOID lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect)",
            "CreateFileW": "HANDLE CreateFileW(const wchar_t *lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void *lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, HANDLE hTemplateFile)",
            "recv": "int recv(int sockfd, void *buf, size_t len, int flags)",
            "ioctl": "int ioctl(int fd, unsigned long request, ...)",
            "operator new": "void *operator new(size_t size)",
        }

        # Check for occurrences of known callees and inject prototypes if needed
        needed_protos = []
        for callee, proto in KNOWN_CALLEES.items():
            if re.search(rf"\b{re.escape(callee)}\s*\(", code) and proto not in code:
                needed_protos.append(f"{proto};")

        # Check STRUCT_CATALOG if supplied
        if struct_catalog:
            for sname, spec in struct_catalog.items():
                if re.search(rf"\b{re.escape(sname)}\b", code):
                    # Inject forward declaration
                    decl = f"typedef struct {sname} {sname};"
                    if decl not in code and decl not in needed_protos:
                        needed_protos.insert(0, decl)

        if needed_protos:
            protos_block = "\n".join(needed_protos) + "\n\n"
            return protos_block + code
        return code

    _CPU_REGISTERS = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30",
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
        "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
        "w24", "w25", "w26", "w27", "w28", "w29", "w30",
    }

    @classmethod
    def declare_undeclared_registers(cls, code: str) -> str:
        """
        Scans C functions for references to CPU hardware registers that lack local
        or parameter declarations, injecting typed zero-initialized local declarations.
        """
        fn_pattern = re.compile(
            r"^(?P<lead>\s*(?:static\s+|inline\s+|extern\s+)*[a-zA-Z0-9_*]+\s+[a-zA-Z0-9_]+\s*\((?P<params>[^)]*)\)\s*\{)",
            re.MULTILINE,
        )
        matches = list(fn_pattern.finditer(code))
        if not matches:
            return code

        result = code
        for m in reversed(matches):
            start_idx = m.start()
            brace_start = result.find("{", start_idx)
            if brace_start == -1:
                continue
            depth = 1
            idx = brace_start + 1
            while idx < len(result) and depth > 0:
                if result[idx] == "{":
                    depth += 1
                elif result[idx] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                idx += 1
            body = result[brace_start + 1 : idx]
            params_str = m.group("params")
            param_tokens = set(re.findall(r"\b[a-zA-Z0-9_]+\b", params_str))

            used_tokens = set(re.findall(r"\b[a-zA-Z0-9_]+\b", body))
            used_regs = used_tokens & cls._CPU_REGISTERS
            undeclared = used_regs - param_tokens

            decl_pattern = re.compile(
                r"\b(?:int|uint[0-9]+_t|int[0-9]+_t|long|char|short|unsigned|void\s*\*|_QWORD|_DWORD|_WORD|_BYTE)\s+(?P<name>[a-zA-Z0-9_]+)\b"
            )
            already_declared = set(dm.group("name") for dm in decl_pattern.finditer(body))
            undeclared = undeclared - already_declared

            if undeclared:
                decls = []
                for reg in sorted(undeclared):
                    is_32 = reg.startswith("e") or reg.endswith("d") or reg.startswith("w")
                    type_name = "uint32_t" if is_32 else "uint64_t"
                    decls.append(f"    {type_name} {reg} = 0;")
                decl_block = "\n" + "\n".join(decls)
                result = result[: brace_start + 1] + decl_block + result[brace_start + 1 :]

        return result

    @classmethod
    def filter(
        cls,
        code: str,
        emit_compilable: bool = True,
        strip_canary: bool = True,
        include_headers: bool = True,
        collapse_strides: bool = True,
        struct_catalog: dict | None = None,
        include_ida_defs: bool = True,
    ) -> str:
        """
        Applies full pipeline of compilable transformations.
        """
        if not code or not emit_compilable:
            return code

        has_ida_tokens = bool(_IDA_TOKEN_RE.search(code))
        result = cls.normalize_ida_idioms(code)
        result = cls.rewrite_types(result)
        result = cls.expand_intrinsics(result)

        if strip_canary:
            result = cls.cleanup_canaries_and_idioms(result)

        if collapse_strides:
            result = cls.collapse_pointer_strides(result)

        result = cls.resolve_callee_types(result, struct_catalog=struct_catalog)
        result = cls.glibc_ctype_support(result)
        result = cls.declare_undeclared_registers(result)

        if include_ida_defs and (has_ida_tokens or bool(_IDA_TOKEN_RE.search(result))):
            if "SUPERGHIDRA_IDA_COMPAT_DEFS_H" not in result:
                result = f"{IDA_COMPAT_DEFS_H}\n{result.lstrip()}"

        if include_headers and "#include <stdint.h>" not in result:
            result = f"{STANDARD_HEADERS}\n{result.lstrip()}"
        elif include_headers and not result.startswith("#include <stdint.h>"):
            result = f"{STANDARD_HEADERS}\n{result.lstrip()}"

        return result


def filter_c_code(code: str, **kwargs: Any) -> str:
    """Filter raw decompiler pseudo-C into standard C99/C++17 code."""
    return CompilableDecompilerFilter.filter(code, **kwargs)
