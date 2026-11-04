#!/usr/bin/env python3
import json, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
rod = open(os.path.join(ROOT, "dump", "4e108a6000.bin"), "rb").read()
datar = open(os.path.join(ROOT, "dump", "4e10d8d000.bin"), "rb").read()
BASE = 0x4E102A4000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
idx = json.load(open(os.path.join(ROOT, "port", "xref-index.json")))
ADRP = {int(k): v for k, v in idx["adrp"].items()}

out = open(os.path.join(ROOT, "port", "semantic3.txt"), "w", encoding="utf-8")
def p(*a):
    print(*a)
    out.write(" ".join(str(x) for x in a) + "\n")

def dis(off, count, label=""):
    p(f"--- {label} @ 0x{off:X}")
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        p(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")

def follow_b(off, depth=0):
    """If word at off is a B, return target."""
    w = int.from_bytes(text[off:off + 4], "little")
    if (w & 0xFC000000) == 0x14000000:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm -= 0x4000000
        return off + imm * 4
    return None

# 1. second-level thunk table
p("== second-level table 0x5E4880..0x5E5100")
off = 0x5E4880
while off < 0x5E5100:
    w = int.from_bytes(text[off:off+4], "little")
    if (w & 0xFC000000) == 0x14000000:
        t = follow_b(off)
        p(f"  0x{off:06X}: b -> 0x{t:06X}")
        off += 4
    else:
        ins = next(md.disasm(text[off:off+4], BASE + off))
        p(f"  0x{off:06X}: {ins.mnemonic} {ins.op_str}")
        off += 4

# chain resolution for the wrapper candidates
p("\n== wrapper -> final impl")
for name, off in [("0x1370D0", 0x1370D0), ("0x1370F0", 0x1370F0), ("0x137100", 0x137100),
                  ("0x137110", 0x137110), ("0x137130", 0x137130), ("0x137150", 0x137150),
                  ("0x137160", 0x137160), ("0x1371A0", 0x1371A0), ("0x1371C0", 0x1371C0),
                  ("0x1371E0", 0x1371E0), ("0x137230", 0x13722C), ("0x137280", 0x137280),
                  ("0x1372A0", 0x1372A0)]:
    # find the b/bl at end of the small function: scan first 8 words
    tgt = None
    for k in range(8):
        t = follow_b(off + 4 * k)
        if t is not None:
            tgt = t
            break
    chain = [hex(tgt)] if tgt else []
    seen = set()
    while tgt is not None and tgt not in seen and len(chain) < 5:
        seen.add(tgt)
        t2 = follow_b(tgt)
        if t2 is None:
            break
        chain.append(hex(t2))
        tgt = t2
    p(f"  wrapper {name}: {' -> '.join(chain)}")

# 2. event region
dis(0x1324E0, 0x540 // 4, "event region 0x1324E0..")

out.close()
print("done")
