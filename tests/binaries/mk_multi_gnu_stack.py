#!/usr/bin/env python3
"""Craft an ELF with TWO PT_GNU_STACK program headers.

The Linux kernel (load_elf_binary() in fs/binfmt_elf.c) and glibc's ld.so both
walk every program header and let the LAST PT_GNU_STACK decide whether the stack
is executable, so checksec must report that one (slimm609/checksec#357).
Toolchains never emit such files, so this patches one produced from test.c.

Usage: mk_multi_gnu_stack.py IN OUT --first FLAGS --last FLAGS
                             [--first-offset N] [--last-offset N]

FLAGS is a combination of R, W and X (or E), e.g. RW or RWX. The first PT_NOTE
header and the existing PT_GNU_STACK header trade places in the table and become
the two PT_GNU_STACK headers (the entry at the lower index gets the --first
flags). p_offset has no meaning for PT_GNU_STACK, so it can be set to a non-zero
value with --first-offset/--last-offset to check that the verdict depends only
on the flags of the last header.
"""
import argparse
import shutil
import struct
import sys

PT_NOTE = 4
PT_GNU_STACK = 0x6474E551
PF = {"X": 1, "E": 1, "W": 2, "R": 4}


def parse_flags(text):
    flags = 0
    for ch in text.upper():
        if ch not in PF:
            sys.exit("bad flag %r in %r (use R, W, X/E)" % (ch, text))
        flags |= PF[ch]
    return flags


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--first", required=True, help="flags of the lower-index PT_GNU_STACK")
    ap.add_argument("--last", required=True, help="flags of the higher-index PT_GNU_STACK")
    ap.add_argument("--first-offset", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--last-offset", type=lambda v: int(v, 0), default=0)
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        data = bytearray(f.read())
    if data[:4] != b"\x7fELF":
        sys.exit("not an ELF file")
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"

    # e_phoff, e_phentsize, e_phnum and the program header layout
    if is64:
        (phoff,) = struct.unpack_from(end + "Q", data, 0x20)
        phentsize, phnum = struct.unpack_from(end + "HH", data, 0x36)
        fmt = end + "IIQQQQQQ"  # type, flags, offset, vaddr, paddr, filesz, memsz, align
    else:
        (phoff,) = struct.unpack_from(end + "I", data, 0x1C)
        phentsize, phnum = struct.unpack_from(end + "HH", data, 0x2A)
        fmt = end + "IIIIIIII"  # type, offset, vaddr, paddr, filesz, memsz, flags, align
    if struct.calcsize(fmt) != phentsize:
        sys.exit("unexpected program header size %d" % phentsize)

    def read(i):
        return list(struct.unpack_from(fmt, data, phoff + i * phentsize))

    def write(i, ent):
        struct.pack_into(fmt, data, phoff + i * phentsize, *ent)

    types = [read(i)[0] for i in range(phnum)]
    if PT_NOTE not in types or PT_GNU_STACK not in types:
        sys.exit("input needs a PT_NOTE and a PT_GNU_STACK program header")
    idx = sorted([types.index(PT_NOTE), types.index(PT_GNU_STACK)])

    def stack_entry(flags, offset):
        # Same shape as what linkers emit: no file/memory extent, 16 byte alignment
        if is64:
            return [PT_GNU_STACK, flags, offset, 0, 0, 0, 0, 0x10]
        return [PT_GNU_STACK, offset, 0, 0, 0, 0, flags, 0x10]

    write(idx[0], stack_entry(parse_flags(args.first), args.first_offset))
    write(idx[1], stack_entry(parse_flags(args.last), args.last_offset))

    with open(args.output, "wb") as f:
        f.write(data)
    # keep the input's permission bits: the result must stay runnable
    shutil.copymode(args.input, args.output)


if __name__ == "__main__":
    main()
