"""Tests for binary_loader: synthetic PE / ELF / Mach-O images plus optional real files."""

import os
import struct
import unittest

import binary_loader as B


# ----------------------------------------------------------------------------------
# Builders
# ----------------------------------------------------------------------------------


def build_pe(bits=64, machine=0x8664, dll=True, text=None):
    """Minimal PE with .text (code), .rdata (exports, imports, debug), .pdata.

    Exports FuncA at .text+0 and FuncB at .text+0x10; `text` overrides the code bytes.
    """
    image_base = 0x180000000 if bits == 64 else 0x10000000
    file_align = 0x200
    text_rva, rdata_rva, pdata_rva = 0x1000, 0x2000, 0x3000
    if text is None:
        text = bytes([0x48, 0x31, 0xC0, 0xC3]) + b"\xCC" * 12 + bytes([0x31, 0xC0, 0xC3]) + b"\xCC" * 13
    text = text.ljust(file_align, b"\xCC")

    rdata = bytearray(0x400)

    def put(off, data):
        rdata[off : off + len(data)] = data
        return rdata_rva + off

    # strings
    dll_name = put(0x200, b"demo.dll\x00")
    name_a = put(0x210, b"FuncA\x00")
    name_b = put(0x218, b"FuncB\x00")
    fwd = put(0x220, b"KERNEL32.Sleep\x00")
    name_fwd = put(0x230, b"SleepFwd\x00")
    imp_lib = put(0x240, b"USER32.dll\x00")
    hint_name = put(0x250, struct.pack("<H", 0) + b"MessageBoxW\x00")
    # export tables at 0x100: functions[3], names[3], ordinals[3]
    funcs = put(0x100, struct.pack("<III", text_rva, text_rva + 0x10, fwd))
    names = put(0x110, struct.pack("<III", name_a, name_b, name_fwd))
    ords = put(0x120, struct.pack("<HHH", 0, 1, 2))
    exp_dir = put(0x000, struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_name, 1, 3, 3, funcs, names, ords))
    exp_size = 0x260  # covers forwarder string so it is recognised as a forwarder
    # imports at 0x60: one descriptor + terminator; ILT at 0x90; IAT at 0xA0
    thunk = "<Q" if bits == 64 else "<I"
    tsz = 8 if bits == 64 else 4
    ilt = put(0x90, struct.pack(thunk, hint_name) + struct.pack(thunk, (1 << (bits - 1)) | 7) + b"\x00" * tsz)
    iat = put(0xB0, struct.pack(thunk, hint_name) + struct.pack(thunk, (1 << (bits - 1)) | 7) + b"\x00" * tsz)
    imp_dir = put(0x60, struct.pack("<IIIII", ilt, 0, 0, imp_lib, iat) + b"\x00" * 20)
    # debug directory at 0x2A0 -> RSDS at 0x300
    rsds_off = 0x300
    put(rsds_off, b"RSDS" + b"\x11" * 16 + struct.pack("<I", 1) + b"C:\\build\\demo.pdb\x00")
    dbg = put(0x2A0, struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, 40, rdata_rva + rsds_off, 0))  # file ptr patched later

    pdata = bytearray(0x200)
    if bits == 64:
        struct.pack_into("<III", pdata, 0, text_rva, text_rva + 4, 0)
        struct.pack_into("<III", pdata, 12, text_rva + 0x10, text_rva + 0x13, 0)
        pdata_size = 24
    else:
        pdata_size = 0

    sections = [(b".text", text_rva, bytes(text), 0x60000020), (b".rdata", rdata_rva, bytes(rdata), 0x40000040),
                (b".pdata", pdata_rva, bytes(pdata), 0x40000040)]
    opt_size = 240 if bits == 64 else 224
    headers_size = 0x400
    e_lfanew = 0x80
    hdr = bytearray(headers_size)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    chars = 0x2022 if dll else 0x0022
    struct.pack_into("<HHIIIHH", hdr, e_lfanew + 4, machine, len(sections), 0, 0, 0, opt_size, chars)
    opt = e_lfanew + 24
    if bits == 64:
        struct.pack_into("<H", hdr, opt, 0x20B)
        struct.pack_into("<I", hdr, opt + 16, text_rva)
        struct.pack_into("<Q", hdr, opt + 24, image_base)
        struct.pack_into("<I", hdr, opt + 108, 16)
        dirs = opt + 112
    else:
        struct.pack_into("<H", hdr, opt, 0x10B)
        struct.pack_into("<I", hdr, opt + 16, text_rva)
        struct.pack_into("<I", hdr, opt + 28, image_base)
        struct.pack_into("<I", hdr, opt + 92, 16)
        dirs = opt + 96
    struct.pack_into("<II", hdr, dirs + 0 * 8, exp_dir, exp_size)
    struct.pack_into("<II", hdr, dirs + 1 * 8, imp_dir, 40)
    struct.pack_into("<II", hdr, dirs + 3 * 8, pdata_rva if pdata_size else 0, pdata_size)
    struct.pack_into("<II", hdr, dirs + 6 * 8, dbg, 28)
    sec_tab = opt + opt_size
    raw = bytearray(hdr)
    for i, (name, rva, blob, ch) in enumerate(sections):
        ptr = len(raw)
        struct.pack_into("<8sIIIIIIHHI", raw, sec_tab + 40 * i, name, len(blob), rva, len(blob), ptr, 0, 0, 0, 0, ch)
        raw += blob
    # patch debug PointerToRawData (rdata is the 2nd section)
    rdata_ptr = headers_size + len(sections[0][2])
    struct.pack_into("<I", raw, rdata_ptr + 0x2A0 + 24, rdata_ptr + rsds_off)
    return bytes(raw), image_base


def build_elf(bits=32, endian="big", machine=8):
    """Minimal ELF shared object with .text, .dynsym/.dynstr and PT_LOAD/PT_DYNAMIC."""
    e = ">" if endian == "big" else "<"
    is64 = bits == 64
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40
    symsize = 24 if is64 else 16
    base_va = 0x10000

    text = b"\x00" * 16
    dynstr = b"\x00libdemo_dep.so\x00exported_fn\x00imported_fn\x00"
    dep, exp_name, imp_name = 1, dynstr.index(b"exported_fn"), dynstr.index(b"imported_fn")
    shstr = b"\x00.text\x00.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00"

    text_off = 0x200
    dynsym_off = text_off + len(text)
    dynstr_off = dynsym_off + 3 * symsize
    dynamic_off = (dynstr_off + len(dynstr) + 7) & ~7
    shstr_off = dynamic_off + 5 * (16 if is64 else 8)
    shoff = (shstr_off + len(shstr) + 7) & ~7

    def sym(name, value, size, info, shndx):
        if is64:
            return struct.pack(e + "IBBHQQ", name, info, 0, shndx, value, size)
        return struct.pack(e + "IIIBBH", name, value, size, info, 0, shndx)

    dynsym = sym(0, 0, 0, 0, 0) + sym(exp_name, base_va + text_off, 8, 0x12, 1) + sym(imp_name, 0, 0, 0x12, 0)
    dynfmt = e + ("qQ" if is64 else "iI")
    dynamic = (struct.pack(dynfmt, 1, dep) + struct.pack(dynfmt, 5, base_va + dynstr_off)
               + struct.pack(dynfmt, 6, base_va + dynsym_off)
               + struct.pack(dynfmt, 10, len(dynstr)) + struct.pack(dynfmt, 0, 0))

    out = bytearray(shoff + 6 * shentsize)
    out[0:4] = b"\x7fELF"
    out[4], out[5], out[6] = (2 if is64 else 1), (2 if endian == "big" else 1), 1
    phoff = ehsize
    if is64:
        struct.pack_into(e + "HHIQQQIHHHHHH", out, 16, 3, machine, 1, base_va + text_off, phoff, shoff, 0,
                         ehsize, phentsize, 2, shentsize, 6, 5)
        struct.pack_into(e + "IIQQQQQQ", out, phoff, 1, 5, 0, base_va, base_va, len(out), len(out), 0x1000)
        struct.pack_into(e + "IIQQQQQQ", out, phoff + phentsize, 2, 6, dynamic_off, base_va + dynamic_off,
                         0, len(dynamic), len(dynamic), 8)
    else:
        struct.pack_into(e + "HHIIIIIHHHHHH", out, 16, 3, machine, 1, base_va + text_off, phoff, shoff, 0,
                         ehsize, phentsize, 2, shentsize, 6, 5)
        struct.pack_into(e + "IIIIIIII", out, phoff, 1, 0, base_va, base_va, len(out), len(out), 5, 0x1000)
        struct.pack_into(e + "IIIIIIII", out, phoff + phentsize, 2, dynamic_off, base_va + dynamic_off, 0,
                         len(dynamic), len(dynamic), 6, 4)
    out[text_off : text_off + len(text)] = text
    out[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    out[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    out[dynamic_off : dynamic_off + len(dynamic)] = dynamic
    out[shstr_off : shstr_off + len(shstr)] = shstr

    def sh(i, name, typ, flags, addr, off, size, link=0, entsize=0):
        o = shoff + i * shentsize
        if is64:
            struct.pack_into(e + "IIQQQQIIQQ", out, o, name, typ, flags, addr, off, size, link, 0, 8, entsize)
        else:
            struct.pack_into(e + "IIIIIIIIII", out, o, name, typ, flags, addr, off, size, link, 0, 4, entsize)

    n = lambda s: shstr.index(s)  # noqa: E731
    sh(1, n(b".text"), 1, 6, base_va + text_off, text_off, len(text))
    sh(2, n(b".dynsym"), 11, 2, base_va + dynsym_off, dynsym_off, len(dynsym), link=3, entsize=symsize)
    sh(3, n(b".dynstr"), 3, 2, base_va + dynstr_off, dynstr_off, len(dynstr))
    sh(4, n(b".dynamic"), 6, 3, base_va + dynamic_off, dynamic_off, len(dynamic), link=3)
    sh(5, n(b".shstrtab"), 3, 0, 0, shstr_off, len(shstr))
    return bytes(out), base_va + text_off


def _uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def build_macho64(cputype=0x0100000C):
    """Thin 64-bit Mach-O dylib: __TEXT(__text,__cstring), symtab, export trie, function starts, LC_MAIN."""
    vm = 0x100000000
    text_off, text_size = 0x1000, 0x20
    cstr_off = text_off + text_size
    cstring = b"hello\x00"
    strtab = b"\x00_exported\x00_imported\x00"
    sym_off = 0x1100
    nlist = (struct.pack("<IBBHQ", strtab.index(b"_exported"), 0x0F, 1, 0, vm + text_off)
             + struct.pack("<IBBHQ", strtab.index(b"_imported"), 0x01, 0, 1 << 8, 0))
    str_off = sym_off + len(nlist)
    # export trie: root -> edge "_exported" -> terminal(flags 0, addr text_off)
    term = _uleb(0) + _uleb(text_off)
    child = _uleb(len(term)) + term + b"\x00"
    edge = b"_exported\x00"
    root_len = 1 + 1 + len(edge) + 1
    root = b"\x00" + b"\x01" + edge + _uleb(root_len)
    trie = root + child
    trie_off = (str_off + len(strtab) + 7) & ~7
    fstarts = _uleb(text_off) + _uleb(0x10) + b"\x00"
    fs_off = trie_off + len(trie)
    total = fs_off + len(fstarts)

    dylib = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_cmd = struct.pack("<IIIIII", 0xC, 24 + ((len(dylib) + 7) & ~7), 24, 0, 0, 0) + dylib.ljust((len(dylib) + 7) & ~7, b"\x00")
    seg = struct.pack("<II16sQQQQiiII", 0x19, 72 + 2 * 80, b"__TEXT", vm, 0x2000, 0, 0x2000, 5, 5, 2, 0)
    seg += struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", vm + text_off, text_size, text_off, 2, 0, 0, 0x80000400, 0, 0, 0)
    seg += struct.pack("<16s16sQQIIIIIIII", b"__cstring", b"__TEXT", vm + cstr_off, len(cstring), cstr_off, 0, 0, 0, 0x2, 0, 0, 0)
    cmds = [
        seg,
        struct.pack("<IIIIII", 0x2, 24, sym_off, 2, str_off, len(strtab)),
        struct.pack("<IIII", 0x80000033, 16, trie_off, len(trie)),
        struct.pack("<IIII", 0x26, 16, fs_off, len(fstarts)),
        struct.pack("<IIQQ", 0x80000028, 24, text_off, 0),
        dylib_cmd,
    ]
    blob = b"".join(cmds)
    out = bytearray(total)
    struct.pack_into("<IiiIIIII", out, 0, 0xFEEDFACF, cputype, 0, 6, len(cmds), len(blob), 0, 0)
    out[32 : 32 + len(blob)] = blob
    out[text_off : text_off + 4] = b"\xC0\x03\x5F\xD6"
    out[cstr_off : cstr_off + len(cstring)] = cstring
    out[sym_off : sym_off + len(nlist)] = nlist
    out[str_off : str_off + len(strtab)] = strtab
    out[trie_off : trie_off + len(trie)] = trie
    out[fs_off : fs_off + len(fstarts)] = fstarts
    return bytes(out), vm


def build_fat(slices):
    """Universal binary from [(cputype, bytes)]."""
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    offset = 0x1000
    entries, payload = b"", b""
    for cputype, blob in slices:
        entries += struct.pack(">iiIII", cputype, 0, offset + len(payload), len(blob), 12)
        payload += blob.ljust((len(blob) + 0xFFF) & ~0xFFF, b"\x00")
    return (header + entries).ljust(offset, b"\x00") + payload


# ----------------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------------


class TestPE(unittest.TestCase):
    def test_pe32plus_dll(self):
        raw, base = build_pe(64)
        img = B.load_binary(raw)
        self.assertEqual((img.format, img.arch, img.bits), ("pe", "x86_64", 64))
        self.assertTrue(img.is_library)
        self.assertEqual(img.image_base, base)
        self.assertEqual(img.entry, base + 0x1000)
        exports = {x.name: x for x in img.exports}
        self.assertEqual(exports["FuncA"].address, base + 0x1000)
        self.assertEqual(exports["FuncA"].ordinal, 1)
        self.assertEqual(exports["FuncB"].address, base + 0x1010)
        self.assertEqual(exports["SleepFwd"].forwarder, "KERNEL32.Sleep")
        self.assertEqual([(i.library, i.name, i.ordinal) for i in img.imports],
                         [("USER32.dll", "MessageBoxW", None), ("USER32.dll", None, 7)])
        self.assertEqual(img.imports[0].address, base + 0x20B0)
        self.assertEqual(img.libraries, ["USER32.dll"])
        self.assertIn(base + 0x1010, img.function_starts)  # from .pdata
        self.assertEqual(img.pdb_path, "C:\\build\\demo.pdb")
        self.assertEqual(img.read_va(img.entry, 4), bytes([0x48, 0x31, 0xC0, 0xC3]))
        self.assertEqual([s.name for s in img.executable_sections()], [".text"])

    def test_pe32_exe(self):
        raw, base = build_pe(32, machine=0x14C, dll=False)
        img = B.load_binary(raw)
        self.assertEqual((img.arch, img.bits, img.is_library), ("x86", 32, False))
        self.assertEqual(img.imports[1].ordinal, 7)  # 32-bit ordinal flag
        self.assertEqual(img.va_to_rva(img.entry), 0x1000)

    def test_arm64_and_armnt_machine(self):
        self.assertEqual(B.load_binary(build_pe(64, machine=0xAA64)[0]).arch, "arm64")
        img = B.load_binary(build_pe(32, machine=0x1C4)[0])
        self.assertEqual(img.arch, "arm")
        self.assertTrue(img.thumb_entry)


class TestELF(unittest.TestCase):
    def test_elf32_big_endian_mips(self):
        raw, fn = build_elf(32, "big", 8)
        img = B.load_binary(raw)
        self.assertEqual((img.format, img.arch, img.bits, img.endian), ("elf", "mips", 32, "big"))
        self.assertTrue(img.is_library)
        self.assertEqual(img.export_map()["exported_fn"], fn)
        self.assertEqual([i.name for i in img.imports], ["imported_fn"])
        self.assertEqual(img.libraries, ["libdemo_dep.so"])

    def test_elf64_little_arm64(self):
        img = B.load_binary(build_elf(64, "little", 0xB7)[0])
        self.assertEqual((img.arch, img.bits, img.endian), ("arm64", 64, "little"))
        self.assertEqual([s.name for s in img.executable_sections()], [".text"])

    def test_stripped_section_table_falls_back_to_dynamic(self):
        raw, fn = build_elf(64, "little", 0xB7)
        raw = bytearray(raw)
        # Forge e_shnum = 0, as protected Android libraries do.
        struct.pack_into("<H", raw, 60, 0)
        img = B.load_binary(bytes(raw))
        self.assertEqual(img.export_map().get("exported_fn"), fn)
        self.assertEqual(img.libraries, ["libdemo_dep.so"])
        self.assertTrue(img.executable_sections(), "PT_LOAD segments should provide code regions")

    def test_non_alloc_sections_do_not_map_low_addresses(self):
        img = B.load_binary(build_elf(64, "little", 0xB7)[0])
        self.assertIsNone(img.va_to_offset(0x10))


class TestMachO(unittest.TestCase):
    def test_thin_arm64_dylib(self):
        raw, vm = build_macho64()
        img = B.load_binary(raw)
        self.assertEqual((img.format, img.arch, img.bits), ("macho", "arm64", 64))
        self.assertTrue(img.is_library)
        self.assertEqual(img.entry, vm + 0x1000)
        self.assertEqual(img.export_map(), {"_exported": vm + 0x1000})
        self.assertEqual([(i.library, i.name) for i in img.imports], [("/usr/lib/libSystem.B.dylib", "_imported")])
        self.assertEqual(img.function_starts, [vm + 0x1000, vm + 0x1010])
        self.assertEqual([s.name for s in img.executable_sections()], ["__TEXT,__text"])
        self.assertEqual(img.read_c_string(vm + 0x1020), "hello")

    def test_universal_binary_slice_selection(self):
        arm, _ = build_macho64(0x0100000C)
        x64, _ = build_macho64(0x01000007)
        fat = build_fat([(0x01000007, x64), (0x0100000C, arm)])
        self.assertEqual(B.detect_format(fat), "macho-fat")
        self.assertEqual(B.load_binary(fat).arch, "arm64")
        self.assertEqual(B.load_binary(fat, prefer_arch="x86_64").arch, "x86_64")


class TestRawAndErrors(unittest.TestCase):
    def test_raw_blob(self):
        img = B.load_binary(b"\x1f\x20\x03\xd5" * 4, raw_arch="arm64", raw_base=0x4000)
        self.assertEqual((img.format, img.arch, img.bits), ("raw", "arm64", 64))
        self.assertEqual(img.read_va(0x4004, 4), b"\x1f\x20\x03\xd5")

    def test_truncated_pe_raises(self):
        raw, _ = build_pe(64)
        with self.assertRaises(B.BinaryFormatError):
            B.load_binary(raw[:0x90])

    def test_java_class_is_not_fat_macho(self):
        self.assertEqual(B.detect_format(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34" + b"\x00" * 16), "raw")


REAL_FILES = {
    "kernel32_x64": r"C:\Windows\System32\kernel32.dll",
    "kernel32_x86": r"C:\Windows\SysWOW64\kernel32.dll",
    "libg_arm64": os.environ.get("SUPERGHIDRA_TEST_ARM64_ELF", ""),
}


class TestRealFiles(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(REAL_FILES["kernel32_x64"]), "Windows x64 kernel32.dll not present")
    def test_kernel32_x64(self):
        img = B.load_binary(REAL_FILES["kernel32_x64"])
        self.assertEqual((img.arch, img.bits, img.is_library), ("x86_64", 64, True))
        names = img.export_map()
        self.assertIn("CreateFileW", names)
        self.assertTrue(any(x.forwarder for x in img.exports))
        self.assertGreater(len(img.function_starts), 1000)

    @unittest.skipUnless(os.path.exists(REAL_FILES["kernel32_x86"]), "WOW64 kernel32.dll not present")
    def test_kernel32_x86(self):
        img = B.load_binary(REAL_FILES["kernel32_x86"])
        self.assertEqual((img.arch, img.bits), ("x86", 32))
        self.assertIn("CreateFileW", img.export_map())

    @unittest.skipUnless(os.path.exists(REAL_FILES["libg_arm64"]), "libg.so not present")
    def test_protected_android_lib(self):
        img = B.load_binary(REAL_FILES["libg_arm64"])
        self.assertEqual(img.arch, "arm64")
        self.assertTrue(any(n.startswith("Java_") for n in img.export_map()))
        self.assertTrue(img.executable_sections())


if __name__ == "__main__":
    unittest.main()
