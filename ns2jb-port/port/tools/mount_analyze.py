#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

BASE = 0x4E102A4000
SEGMENTS = (
    (0x000000, "4e102a4000.bin"),
    (0x602000, "4e108a6000.bin"),
    (0xAE9000, "4e10d8d000.bin"),
    (0xB34000, "4e10dd8000.bin"),
)


class Dump:
    def __init__(self, root):
        self.root = root
        self.segments = [(start, (root / "dump" / name).read_bytes())
                         for start, name in SEGMENTS]

    def read(self, offset, size):
        for start, data in self.segments:
            relative = offset - start
            if 0 <= relative and relative + size <= len(data):
                return data[relative:relative + size]
        return None

    def u32(self, offset):
        data = self.read(offset, 4)
        return struct.unpack("<I", data)[0] if data is not None else None

    def u64(self, offset):
        data = self.read(offset, 8)
        return struct.unpack("<Q", data)[0] if data is not None else None

    def describe(self, offset):
        value = self.u64(offset)
        if value is None:
            return "not dumped"
        relative = value - BASE if BASE <= value < BASE + 0x1000000 else None
        suffix = f" -> module {relative:#x}" if relative is not None else ""
        return f"qword {value:#x}{suffix}"


def adrp(word, pc):
    if word & 0x9F000000 != 0x90000000:
        return None
    immediate = ((word >> 5) & 0x7FFFF) << 2 | (word >> 29) & 3
    if immediate & 1 << 20:
        immediate -= 1 << 21
    return word & 0x1F, (pc & ~0xFFF) + (immediate << 12)


def add_immediate(word):
    if word & 0xFF000000 != 0x91000000 or word & 0x400000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) << (12 if word & 0x800000 else 0)


def load_store(word):
    if word & 0x3B000000 != 0x39000000:
        return None
    size = 1 << (word >> 30)
    return {
        "load": bool(word & 0x400000),
        "size": size,
        "rd": word & 0x1F,
        "rn": (word >> 5) & 0x1F,
        "offset": ((word >> 10) & 0xFFF) * size,
    }


def branch(word, pc):
    if word & 0xFC000000 not in (0x14000000, 0x94000000):
        return None
    immediate = word & 0x3FFFFFF
    if immediate & 1 << 25:
        immediate -= 1 << 26
    return ("bl" if word & 0x80000000 else "b", pc + immediate * 4)


def show_references(dump, start, end):
    pages = {}
    for pc in range(start, end, 4):
        word = dump.u32(pc)
        if word is None:
            continue
        page = adrp(word, pc)
        if page:
            register, target = page
            pages[register] = target
            print(f"{pc:#010x}  {word:08x}  adrp x{register}, {target:#x}")
            continue
        add = add_immediate(word)
        if add and add[1] in pages:
            rd, rn, immediate = add
            target = pages[rn] + immediate
            pages[rd] = target & ~0xFFF if rd == rn else target
            print(f"{pc:#010x}  {word:08x}  add x{rd}, x{rn}, {immediate:#x} ; {target:#x} ({dump.describe(target)})")
            continue
        memory = load_store(word)
        if memory and memory["rn"] in pages:
            target = pages[memory["rn"]] + memory["offset"]
            operation = "ldr" if memory["load"] else "str"
            print(f"{pc:#010x}  {word:08x}  {operation} x{memory['rd']}, [x{memory['rn']}, {memory['offset']:#x}] ; {target:#x} ({dump.describe(target)})")
            continue
        target = branch(word, pc)
        if target:
            operation, destination = target
            print(f"{pc:#010x}  {word:08x}  {operation} {destination:#x}")


def main():
    parser = argparse.ArgumentParser(description="Trace static references in the Civ7 SDK dump without executing code")
    parser.add_argument("start", type=lambda value: int(value, 0))
    parser.add_argument("end", type=lambda value: int(value, 0))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    show_references(Dump(args.root), args.start, args.end)


if __name__ == "__main__":
    main()
