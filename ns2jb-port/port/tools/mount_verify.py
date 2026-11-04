#!/usr/bin/env python3
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x4E102A4000
SEGMENTS = (
    (0x000000, "4e102a4000.bin"),
    (0x602000, "4e108a6000.bin"),
    (0xAE9000, "4e10d8d000.bin"),
    (0xB34000, "4e10dd8000.bin"),
)
GET_FREE_SPACE_OFFSET = 0xA75D0
GET_FREE_SPACE_BYTES = "ff4301d1fd7b01a9f71300f9f65703a9f44f04a9fd43009157c08b52f705a072ff0700f9f40301aaf30300aaf503172a90011594c001003666fd1494f60300aa"
QUERY_MEMORY_OFFSET = 0x168B0C
QUERY_MEMORY_BYTES = "e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6"


class Dump:
    def __init__(self, root):
        self.segments = [(start, root / "dump" / name) for start, name in SEGMENTS]

    def read(self, offset, size):
        for start, path in self.segments:
            data = path.read_bytes()
            relative = offset - start
            if 0 <= relative and relative + size <= len(data):
                return data[relative:relative + size]
        raise AssertionError(f"module range {offset:#x}..{offset + size:#x} is not dumped")

    def u32(self, offset):
        return struct.unpack("<I", self.read(offset, 4))[0]

    def u64(self, offset):
        return struct.unpack("<Q", self.read(offset, 8))[0]


def branch_target(word, pc):
    assert word & 0xFC000000 == 0x14000000
    immediate = word & 0x3FFFFFF
    if immediate & 1 << 25:
        immediate -= 1 << 26
    return pc + immediate * 4


def adrp_add_target(dump, pc):
    first, second = dump.u32(pc), dump.u32(pc + 4)
    assert first & 0x9F000000 == 0x90000000
    assert second & 0xFF800000 == 0x91000000
    assert first & 0x1F == second & 0x1F == (second >> 5) & 0x1F
    immediate = ((first >> 5) & 0x7FFFF) << 2 | (first >> 29) & 3
    if immediate & 1 << 20:
        immediate -= 1 << 21
    return (pc & ~0xFFF) + (immediate << 12) + ((second >> 10) & 0xFFF)


def verify_bytes(dump, offset, expected, label):
    wanted = bytes.fromhex(expected)
    actual = dump.read(offset, len(wanted))
    assert actual == wanted, f"{label}: bytes differ at {offset:#x}"
    print(f"OK {label}: offset={offset:#x}, bytes={len(wanted)}")


def main():
    root = Path(__file__).resolve().parents[2]
    dump = Dump(root)
    layout = json.loads((root / "port/sdk-layout.civ7.json").read_text())
    proxy = json.loads((root / "port/civ7-app/sdk-proxy-code.json").read_text())

    for index, entry in enumerate(layout["verifiedFunctions"]):
        verify_bytes(dump, entry["offset"], entry["bytes"], f"layout.verifiedFunctions[{index}]")
    verify_bytes(dump, proxy["functionOffset"], proxy["bytes"], "fsp-srv proxy getter")
    verify_bytes(dump, GET_FREE_SPACE_OFFSET, GET_FREE_SPACE_BYTES, "GetFreeSpaceSize")
    verify_bytes(dump, QUERY_MEMORY_OFFSET, QUERY_MEMORY_BYTES, "svcQueryMemory")

    head = layout["mountTableOffset"]
    assert head == adrp_add_target(dump, 0xAAF18), "find wrapper does not address emitted mount head"
    assert branch_target(dump.u32(0xAAF20), 0xAAF20) == 0x5E7FF0
    assert branch_target(dump.u32(0xAAF40), 0xAAF40) == 0x5E7FE0
    assert dump.u64(0xB272D0) == BASE + 0xA4420
    assert dump.u64(0xB272C8) == BASE + 0xA4360
    previous, following = dump.u64(head), dump.u64(head + 8)
    assert previous != following and previous & 7 == following & 7 == 0
    assert 0 < previous < 1 << 39 and 0 < following < 1 << 39
    print(f"OK mount head: offset={head:#x}, dumped links={previous:#x}/{following:#x}")

    assert proxy["globalOffset"] == 0xB4B450
    assert adrp_add_target(dump, 0xBD93C) == proxy["globalOffset"] + 8
    assert adrp_add_target(dump, 0xBD998) == proxy["globalOffset"]
    assert adrp_add_target(dump, 0xBDA68) == 0x8E0F8A
    assert dump.read(0x8E0F8A, 8) == b"fsp-srv\0"
    print(f"OK proxy global: offset={proxy['globalOffset']:#x}, initializer service='fsp-srv' (BSS contents runtime-only)")

    for site in (0xA7674, 0xA76E0):
        assert adrp_add_target(dump, site) == 0x8D5B9D
    assert dump.read(0x8D5B9D, 17) == b"GetFreeSpaceSize\0"
    print("OK free-space identity: public wrapper references 'GetFreeSpaceSize'")

    for start, path in dump.segments:
        print(f"DUMP {path.name}: module={start:#x}, bytes={path.stat().st_size:#x}, sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    print("All emitted mount/proxy offsets and probe helper offsets verified.")


if __name__ == "__main__":
    main()
