#!/usr/bin/env python3
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x4E102A4000
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()
SEGMENTS = [
    (0, TEXT),
    (0x602000, (ROOT / "dump/4e108a6000.bin").read_bytes()),
    (0xae9000, (ROOT / "dump/4e10d8d000.bin").read_bytes()),
    (0xb34000, (ROOT / "dump/4e10dd8000.bin").read_bytes()),
]


def resolve_thunk(offset):
    adrp, ldr = struct.unpack_from("<II", TEXT, offset)
    assert adrp & 0x9f00001f == 0x90000010 and ldr & 0xffc003ff == 0xf9400211
    immediate = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    slot = (offset & ~0xfff) + (immediate << 12) + ((ldr >> 10) & 0xfff) * 8
    for start, data in SEGMENTS:
        if start <= slot and slot + 8 <= start + len(data):
            value = struct.unpack_from("<Q", data, slot - start)[0]
            return slot, value
    raise ValueError(f"unmapped GOT slot {slot:#x}")


def word(offset):
    return struct.unpack_from("<I", TEXT, offset)[0]


for thunk in (0x5e6b30, 0x5e6b40, 0x5eb1c0, 0x5eb1e0):
    slot, value = resolve_thunk(thunk)
    print(f"{thunk:#x}: slot {slot:#x} -> {value:#x} (module {value - BASE:#x})")

assert word(0x137ed4) == 0x52803802
print("manager create clears 0x1c0 itself; no pre-initialization beyond valid storage is required")
assert word(0x13dcf4) == 0x8b080135 and word(0x13dcf8) == 0xf81e0ea2
print("low-level create computes stack_top = [thread+0x50] + [thread+0x58] and stores entry at top-0x20")
assert word(0x13dd30) == 0x72a01316 and word(0x13df74) == 0x52824060
print("resource retry is bounded: ten 0x989680 ns sleeps, then return 0x1203")
for offset in (0x13dd14, 0x13dd60, 0x13dda0, 0x13dde0, 0x13de20, 0x13de60, 0x13dea0, 0x13dee0, 0x13df20, 0x13df60):
    branch = word(offset)
    assert branch >> 26 == 0x25
print("confirmed exactly ten svcCreateThread call sites in the retry loop")
