#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x4E102A4000
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()


def disasm(start, size):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ModuleNotFoundError:
        from app_a64 import disassemble
        for address, word, mnemonic, operands in disassemble(TEXT[start:start + size], BASE + start):
            print(f"{address - BASE:08x}: {word:08x}  {mnemonic:8s} {operands}")
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    for ins in md.disasm(TEXT[start:start + size], BASE + start):
        print(f"{ins.address - BASE:08x}: {ins.bytes.hex()}  {ins.mnemonic:8s} {ins.op_str}")


def branch_sites(target, link=None):
    for off in range(0, len(TEXT) - 3, 4):
        word = struct.unpack_from("<I", TEXT, off)[0]
        opcode = word >> 26
        if opcode not in (0x05, 0x25) or (link is not None and (opcode == 0x25) != link):
            continue
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        if off + imm * 4 == target:
            print(f"{off:08x}: {'bl' if opcode == 0x25 else 'b'} 0x{target:x}")


def exact(hex_bytes):
    needle = bytes.fromhex(hex_bytes)
    at = TEXT.find(needle)
    while at >= 0:
        print(f"{at:08x}")
        at = TEXT.find(needle, at + 1)


def hexdump(start, size):
    for off in range(start, start + size, 4):
        print(f"{off:08x}: {TEXT[off:off + 4].hex()}")


def segments():
    return [
        (0, "text", TEXT),
        (0x602000, "rodata", (ROOT / "dump/4e108a6000.bin").read_bytes()),
        (0xae9000, "data", (ROOT / "dump/4e10d8d000.bin").read_bytes()),
        (0xb34000, "data-rw", (ROOT / "dump/4e10dd8000.bin").read_bytes()),
    ]


def pointers(target):
    needle = struct.pack("<Q", BASE + target)
    for module_offset, name, data in segments():
        at = data.find(needle)
        while at >= 0:
            print(f"{module_offset + at:08x} {name}")
            at = data.find(needle, at + 1)


def ascii_hits(text):
    needle = text.encode()
    for module_offset, name, data in segments():
        at = data.find(needle)
        while at >= 0:
            end = data.find(b"\0", at)
            print(f"{module_offset + at:08x} {name} {data[at:end]!r}")
            at = data.find(needle, at + 1)


def address_xrefs(target):
    target_page = target & ~0xfff
    for off in range(0, len(TEXT) - 20, 4):
        word = struct.unpack_from("<I", TEXT, off)[0]
        if word & 0x9f000000 != 0x90000000:
            continue
        imm = ((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3
        if imm & 0x100000:
            imm -= 0x200000
        if (off & ~0xfff) + (imm << 12) != target_page:
            continue
        reg = word & 31
        for delta in range(4, 20, 4):
            ins = struct.unpack_from("<I", TEXT, off + delta)[0]
            if (ins >> 5) & 31 != reg:
                continue
            computed = None
            if ins & 0xff000000 == 0x91000000:
                immediate = ((ins >> 10) & 0xfff) << (12 if (ins >> 22) & 1 else 0)
                computed = target_page + immediate
            elif ins & 0xffc00000 in (0xf9400000, 0xb9400000):
                scale = 8 if ins & 0xffc00000 == 0xf9400000 else 4
                computed = target_page + ((ins >> 10) & 0xfff) * scale
            if computed == target:
                print(f"{off:08x} +0x{delta:x}: {word:08x} {ins:08x}")


def thunk_sites(target):
    data_segments = segments()
    for off in range(0, len(TEXT) - 16, 4):
        adrp, ldr = struct.unpack_from("<II", TEXT, off)
        if adrp & 0x9f00001f != 0x90000010 or ldr & 0xffc003ff != 0xf9400211:
            continue
        imm = ((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3
        if imm & 0x100000:
            imm -= 0x200000
        slot = (off & ~0xfff) + (imm << 12) + ((ldr >> 10) & 0xfff) * 8
        value = None
        for start, _, data in data_segments:
            if start <= slot and slot + 8 <= start + len(data):
                value = struct.unpack_from("<Q", data, slot - start)[0]
                break
        if value != BASE + target:
            continue
        print(f"thunk {off:08x} slot {slot:08x}")
        branch_sites(off)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    dis = sub.add_parser("dis")
    dis.add_argument("start", type=lambda value: int(value, 0))
    dis.add_argument("size", type=lambda value: int(value, 0))
    sites = sub.add_parser("sites")
    sites.add_argument("target", type=lambda value: int(value, 0))
    sites.add_argument("--link", action="store_true")
    sites.add_argument("--direct", action="store_true")
    find = sub.add_parser("exact")
    find.add_argument("bytes")
    dump = sub.add_parser("hex")
    dump.add_argument("start", type=lambda value: int(value, 0))
    dump.add_argument("size", type=lambda value: int(value, 0))
    ptr = sub.add_parser("pointers")
    ptr.add_argument("target", type=lambda value: int(value, 0))
    strings = sub.add_parser("ascii")
    strings.add_argument("text")
    xrefs = sub.add_parser("xrefs")
    xrefs.add_argument("target", type=lambda value: int(value, 0))
    thunks = sub.add_parser("thunks")
    thunks.add_argument("target", type=lambda value: int(value, 0))
    args = parser.parse_args()
    if args.command == "dis":
        disasm(args.start, args.size)
    elif args.command == "sites":
        branch_sites(args.target, True if args.link else False if args.direct else None)
    elif args.command == "exact":
        exact(args.bytes)
    elif args.command == "hex":
        hexdump(args.start, args.size)
    elif args.command == "ascii":
        ascii_hits(args.text)
    elif args.command == "xrefs":
        address_xrefs(args.target)
    elif args.command == "thunks":
        thunk_sites(args.target)
    else:
        pointers(args.target)


if __name__ == "__main__":
    main()
