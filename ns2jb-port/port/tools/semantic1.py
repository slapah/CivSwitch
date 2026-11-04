#!/usr/bin/env python3
"""Semantic identification using the xref index + targeted disassembly."""
import json, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
rod = open(os.path.join(ROOT, "dump", "4e108a6000.bin"), "rb").read()
datar = open(os.path.join(ROOT, "dump", "4e10d8d000.bin"), "rb").read()
BASE = 0x4E102A4000
ROD_MOD = 0x602000
DATAR_OFF = 0xAE9000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

idx = json.load(open(os.path.join(ROOT, "port", "xref-index.json")))
BL = {int(k): v for k, v in idx["bl"].items()}
B = {int(k): v for k, v in idx["b"].items()}
SVC = idx["svc"]
ADRP = {int(k): v for k, v in idx["adrp"].items()}

out = open(os.path.join(ROOT, "port", "semantic.txt"), "w", encoding="utf-8")
def p(*a):
    print(*a)
    out.write(" ".join(str(x) for x in a) + "\n")

def dis(off, count, label=""):
    p(f"--- {label} @ 0x{off:X}")
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        p(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")

# 1. svc table
p("== svc sites (off, N)")
for off, n in sorted(SVC):
    p(f"  0x{off:06X} svc #{n} (0x{n:X})")

# 2. who branches to 0x13E484 (ThreadManagerImpl GetThreadAvailableCoreMask)
p("\n== B/BL edges into 0x13E484 (Impl GetThreadAvailableCoreMask)")
p("  B from:", [hex(x) for x in B.get(0x13E484, [])])
p("  BL from:", [hex(x) for x in BL.get(0x13E484, [])])

# 3. svc #0x10 wrapper and its B-callers
for want in (0x08, 0x09, 0x0A, 0x0B, 0x10, 0x18, 0x1A, 0x1B, 0x1C, 0x1D, 0x34, 0x35):
    sites = [off for off, n in SVC if n == want]
    p(f"== svc #{want:#x} sites: {[hex(s) for s in sites]}")
    for s in sites:
        # wrapper starts: scan back up to 3 words for str pre-index
        start = s
        for back in range(1, 4):
            w = int.from_bytes(text[s - 4 * back:s - 4 * back + 4], "little")
            if (w & 0xFFE00000) == 0xF8000000 and w & 0x1F0000 and (w & 0xC00) == 0xC00:
                pass
        p(f"   B-callers of area near 0x{s:X}:", [hex(c) for c in B.get(s, [])],
          "of s-4:", [hex(c) for c in B.get(s - 4, [])])
out.close()
print("done part 1")
