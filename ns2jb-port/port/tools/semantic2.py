#!/usr/bin/env python3
import json, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
BASE = 0x4E102A4000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

idx = json.load(open(os.path.join(ROOT, "port", "xref-index.json")))
BL = {int(k): v for k, v in idx["bl"].items()}
B = {int(k): v for k, v in idx["b"].items()}
SVC = idx["svc"]

out = open(os.path.join(ROOT, "port", "semantic2.txt"), "w", encoding="utf-8")
def p(*a):
    print(*a)
    out.write(" ".join(str(x) for x in a) + "\n")

def dis(off, count, label=""):
    p(f"--- {label} @ 0x{off:X}")
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        p(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")

# svc wrapper starts: walk back over leading str pre-index
def wrapper_start(s):
    w = int.from_bytes(text[s - 4:s], "little")
    if (w & 0xFFFFF000) == 0xF81F0000 or (w & 0xFFC00C00) == 0xF8000C00:
        return s - 4
    return s

p("== BL callers into svc wrappers of interest")
for want, nm in [(0x08, "CreateThread"), (0x09, "StartThread"), (0x0A, "ExitThread"),
                 (0x0B, "SleepThread"), (0x10, "GetCurrentProcessorNumber"),
                 (0x18, "WaitSynchronization"), (0x22, "SendSyncRequest"),
                 (0x1C, "WaitProcessWideKeyAtomic"), (0x1D, "SignalProcessWideKey"),
                 (0x34, "WaitForAddress"), (0x35, "SignalToAddress")]:
    for s, n in SVC:
        if n == want:
            st = wrapper_start(s)
            p(f"svc {n:#x} {nm}: svc@0x{s:X} wrapper@0x{st:X} BLfrom={[hex(c) for c in BL.get(st, [])]} "
              f"Bfrom={[hex(c) for c in B.get(st, [])]}")

# thread wrapper cluster region
dis(0x137040, 0x270 // 4, "thread wrapper cluster")
# impl cluster around svc tail-branch sites
dis(0x13E200, 0x420 // 4, "impl cluster 0x13E200..0x13E620")
out.close()
print("done")
