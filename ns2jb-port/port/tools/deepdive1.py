#!/usr/bin/env python3
"""Deep-dive: svc region bytes, memcpy/memmove boundaries, thunk table, pass-2 search."""
import json, os
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
words = np.frombuffer(text, dtype=np.uint32)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
BASE = 0x4E102A4000

print("== bytes at 0x168B0C:", text[0x168B0C:0x168B20].hex())

def dis(off, count, label=""):
    print(f"--- {label} @ 0x{off:X}")
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        print(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")

# mem* region: find function starts (end at ret/br) between 0x5224E0 and 0x522AF0
print("== scan mem region for ret-terminated functions")
off = 0x5224E0
end = 0x522B20
while off < end:
    # find next ret
    start = off
    code = text[off:end]
    for ins in md.disasm(code, BASE + off):
        off = ins.address - BASE + 4
        if ins.mnemonic in ("ret", "retab") or (ins.mnemonic == "br"):
            break
    print(f"  function 0x{start:06X}..0x{off:06X} ({(off-start)} bytes)")

dis(0x5224E0, 8, "fn A (contract memcpy)")
# show a bit of each discovered function start later if needed

# thunk table enumeration around socket cluster
print("== thunk table 0x14D200..0x14D560")
off = 0x14D200
while off < 0x14D560:
    w = words[off // 4]
    if (w & 0xFC000000) == 0x14000000:  # B
        imm = w & 0x03FFFFFF
        if imm & 0x02000000: imm -= 0x04000000
        tgt = off + imm * 4
        print(f"  thunk 0x{off:06X} -> 0x{tgt:06X}")
        off += 0x10
    else:
        off += 4
