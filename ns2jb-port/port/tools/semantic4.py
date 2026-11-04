#!/usr/bin/env python3
import json, os, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
rod = open(os.path.join(ROOT, "dump", "4e108a6000.bin"), "rb").read()
datar = open(os.path.join(ROOT, "dump", "4e10d8d000.bin"), "rb").read()
datarw = open(os.path.join(ROOT, "dump", "4e10dd8000.bin"), "rb").read()
BASE = 0x4E102A4000
TEXT_END = BASE + 0x602000
DATAR_OFF = 0xAE9000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
idx = json.load(open(os.path.join(ROOT, "port", "xref-index.json")))
BL = {int(k): v for k, v in idx["bl"].items()}
B = {int(k): v for k, v in idx["b"].items()}
ADRP = {int(k): v for k, v in idx["adrp"].items()}

out = open(os.path.join(ROOT, "port", "semantic4.txt"), "w", encoding="utf-8")
def p(*a):
    print(*a)
    out.write(" ".join(str(x) for x in a) + "\n")

def dis(off, count, label=""):
    p(f"--- {label} @ 0x{off:X}")
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        p(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")

def rd_datar(modoff):
    fo = modoff - DATAR_OFF
    if 0 <= fo <= len(datar) - 8:
        return struct.unpack_from("<Q", datar, fo)[0]
    return None

# 1. Resolve GOT targets for wrapper thunks.
# thunk at T (in 0x5E4880 table) -> slot module offset = 0xB25000 + 0x718 + (T-0x5E4880)//0x10*8
p("== GOT resolution of thread-family wrapper thunks")
def got_target(thunk):
    slot = 0xB25000 + 0x718 + (thunk - 0x5E4880) // 0x10 * 8
    v = rd_datar(slot)
    if v is None:
        return slot, None
    if TEXT_END and BASE <= v < TEXT_END:
        return slot, f"in-module 0x{v - BASE:X}"
    return slot, f"external 0x{v:X}"

for name, thunk in [("0x1370D0 w", 0x5E4FA0), ("0x1370F0 w", 0x5E4FB0), ("0x137100 t", 0x5E4FC0),
                    ("0x137110 w", 0x5E4FD0), ("0x137130 w", 0x5E4FE0), ("0x137150 w", 0x5E4FF0),
                    ("0x1371A0 SetTCM", 0x5E5010), ("0x1371C0 GetTCM", 0x5E5030),
                    ("0x1371E0 w", 0x5E5040), ("0x137230 chain", 0x5E5060),
                    ("0x137280 w(+0x3f0)", 0x5E5090), ("0x137060 lock?", 0x5E4880),
                    ("0x137060 impl", 0x5E48A0), ("0x1328F4 waitHelper", 0x5E4940),
                    ("0x13286C tickFreq?", 0x5E48F0)]:
    slot, tgt = got_target(thunk)
    p(f"  {name}: thunk 0x{thunk:X} slot 0x{slot:X} -> {tgt}")

# 2. find function start containing an offset (scan back to ret/udf boundary)
def fn_start(off):
    o = off
    while o > 0:
        o -= 4
        w = int.from_bytes(text[o:o+4], "little")
        if w == 0xD65F03C0 or w == 0x00000000:  # ret or udf
            return o + 4
    return 0

# sleep impl candidates: functions containing B to svc#0xB wrapper (0x168B54)
for site in (0x13E270, 0x13EFD4):
    st = fn_start(site - 4)
    p(f"== B->svcSleepThread at 0x{site:X}; function start guess 0x{st:X}")
    dis(st, min((site - st) // 4 + 3, 24), "sleep-impl candidate")

# 3. svc#8/9/0xA caller regions
dis(0x13DD00, 0x120 // 4, "CreateThread caller cluster head")
dis(0x13E080, 0x80 // 4, "ExitThread/StartThread impl region")

# 4. pthread magic search: sub w8, w8, #3 ; cmp w8, #1
pat = bytes.fromhex('080d0351') + bytes.fromhex('1f050071')
at = 0
sites = []
while True:
    i = text.find(pat, at)
    if i < 0: break
    sites.append(i); at = i + 4
p("== 'sub w8,w8,#3; cmp w8,#1' sites:", [hex(s) for s in sites])
for s in sites:
    st = fn_start(s)
    p(f"   site 0x{s:X} fn start 0x{st:X}")

# 5. posix_memalign: cmp x1, #8 sites
pat = (0xF100203F).to_bytes(4, "little")
at = 0
sites = []
while True:
    i = text.find(pat, at)
    if i < 0: break
    sites.append(i); at = i + 4
p("== 'cmp x1,#8' sites:", [hex(s) for s in sites][:40], "total", len(sites))

# 6. tpidr mrs sites
p("== mrs tpidr* sites")
import re
for off in range(0, len(text) - 4, 4):
    w = int.from_bytes(text[off:off+4], "little")
    if (w & 0xFFF00000) == 0xD5300000 or (w & 0xFFF00000) == 0xD5300000:
        pass
# simpler: disassemble-scan all mrs
md2 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
tp = []
for ins in md2.disasm(text, BASE):
    if ins.mnemonic == "mrs" and "tpidr" in ins.op_str:
        tp.append((ins.address - BASE, ins.op_str))
p("  total tpidr reads:", len(tp))
for o, s in tp[:40]:
    p(f"   0x{o:06X}: mrs {s}")

out.close()
print("done")
