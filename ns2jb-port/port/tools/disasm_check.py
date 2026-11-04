#!/usr/bin/env python3
"""Verify anchor candidates and disassemble key regions of the Civ7 sdk dump."""
import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dis(off, count, label=""):
    print(f"--- {label} @ file+0x{off:X}")
    code = text[off:off + count * 4]
    for ins in md.disasm(code, 0x4E102A4000 + off):
        print(f"  +0x{ins.address - 0x4E102A4000:06X}: {ins.mnemonic:8s} {ins.op_str}")

# svcQueryMemory expected at 0x168B0C
dis(0x168B00, 12, "svcQueryMemory area")
# memset unique masked hit
dis(0x522AF0, 16, "memset candidate")
# memcpy anchor candidate
dis(0x5224E0, 16, "memcpy candidate (anchor = memcpy - 0x5224E0)")
# socket cluster per anchor-relative contract offsets (if anchor == module base)
for name, off in [("Recv", 0x14D310), ("Send", 0x14D340), ("Accept", 0x14D390),
                  ("Bind", 0x14D3B0), ("Connect", 0x14D3C0), ("GetSockName", 0x14D410),
                  ("Listen", 0x14D440), ("SetSockOpt", 0x14D460), ("Socket", 0x14D4C0),
                  ("Close", 0x14D510)]:
    dis(off, 6, f"socket cluster {name}")
