#!/usr/bin/env python3
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()
REFERENCE = json.loads((ROOT / "ns2jb-main/engine/switch2/app/thread-code.json").read_text())
RUN = ROOT / "port/engine/runs/switch2-QnPKJX"


def word(offset):
    return struct.unpack_from("<I", TEXT, offset)[0]


def resolve_thunk(offset):
    adrp, ldr = struct.unpack_from("<II", TEXT, offset)
    immediate = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    slot = (offset & ~0xfff) + (immediate << 12) + ((ldr >> 10) & 0xfff) * 8
    segments = [
        (0x602000, "4e108a6000.bin"),
        (0xae9000, "4e10d8d000.bin"),
        (0xb34000, "4e10dd8000.bin"),
    ]
    for start, name in segments:
        data = (ROOT / "dump" / name).read_bytes()
        if start <= slot and slot + 8 <= start + len(data):
            value = struct.unpack_from("<Q", data, slot - start)[0]
            return slot, value
    raise ValueError(f"GOT slot outside dumps: {slot:#x}")


def ror(value, rotate, width):
    return ((value >> rotate) | (value << (width - rotate))) & ((1 << width) - 1)


def logical_immediate(word):
    assert word & 0x80000000 and (word >> 31) & 1
    n = (word >> 22) & 1
    immr = (word >> 16) & 0x3f
    imms = (word >> 10) & 0x3f
    combined = (n << 6) | imms
    length = combined.bit_length() - 1
    levels = (1 << length) - 1
    size = imms & levels
    rotate = immr & levels
    width = 1 << length
    return ror((1 << (size + 1)) - 1, rotate, width)


assert word(0x14219c) == 0xaa0303f5  # mov x21,x3 (frame base)
assert word(0x1421a8) == 0xaa0003f3  # mov x19,x0 (output slot)
assert word(0x142340) == 0x910c42f4  # add x20,x23,#0x310
assert word(0x14234c) == 0x8b204ee8  # add x8,x21,w0,uxtw #3
assert word(0x142354) == 0xf9004114  # str x20,[x8,#0x80]
assert word(0x142364) == 0xf9000268  # str x8,[x19]
mask = logical_immediate(word(0x14235c))
print(f"decoded logical immediate: 0x{mask:x}")
assert mask == 7
print(f"0x14235c: ands x8,x23,#0x{mask:x}")
print("0x142364 stores x8 to the caller slot; the 8-byte-aligned thread object yields zero")
print("0x142340/0x142354: actual thread object+0x310 is stored at [frameBase + (w0 << 3) + 0x80]")
print("0x142370 returns w24, which is zero only after the success output store")
for thunk in (0x5eab30, 0x5eab40):
    slot, value = resolve_thunk(thunk)
    module_offset = value - 0x4e102a4000
    print(f"thunk {thunk:#x}: GOT {slot:#x} -> {value:#x} (module {module_offset:#x})")

reference_create = bytes.fromhex(REFERENCE["functions"]["create"]["bytes"])
assert reference_create[:20] == bytes.fromhex("ff8303d1fd7b08a9fd030291fc6f09a9fa670aa9")
assert reference_create[32:48] == bytes.fromhex("f40303aaf50302aaf30300aae10300b4")
print("SmileBASIC prologue: x20=arg, x21=entry, x19=slot, null attr branches to defaults; Civ7 has the same public argument ABI")
reference_result_store = reference_create.rfind(bytes.fromhex("600200f9"))
assert reference_result_store > len(reference_create) - 80
print(f"SmileBASIC tail stores the actual internal thread pointer to the output slot at create+{reference_result_store:#x}, unlike Civ7's x23&7 store")
assert word(0x1422f8) == 0xa91c56f6  # stp x22,x21,[x23,#0x1c0]
print("0x1422f8 stores entry and argument at thread object+0x1c0/+0x1c8; candidate-0x150/-0x148 must match them")

plan = json.loads((RUN / "switch2/app/qualify-1793639025723-plan.json").read_text())
base = plan["base"]
sdk = plan["sdk"]
print(f"run frame base: {base:#x}; output slot: {base - 0x1e000:#x}; sdk: {sdk:#x}")
print("w0 is the helper return at 0x142348 and is not saved in the frame; its value is not statically known")
print("bounded diagnostic candidates only (w0=0..3, not a claimed upper bound):")
for index in range(4):
    candidate = base + 0x80 + index * 8
    print(f"  w0={index}: read pointer at {candidate:#x}; after mapping checks, expect entry at pointer-0x150={sdk + 0x5511b4:#x}, argument at pointer-0x148={base:#x}")
print("Read only the four candidate qwords and validated object fields; stop without calling a pointer if none matches")
