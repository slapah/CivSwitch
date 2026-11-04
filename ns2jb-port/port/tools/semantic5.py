#!/usr/bin/env python3
"""Semantic pass 5: name remaining Civ7 symbols via GOT resolution, register-agnostic
pattern scans, xref scans and disassembly. Output: port/semantic5.txt"""
import json, os, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
rod = open(os.path.join(ROOT, "dump", "4e108a6000.bin"), "rb").read()
datar = open(os.path.join(ROOT, "dump", "4e10d8d000.bin"), "rb").read()
datarw = open(os.path.join(ROOT, "dump", "4e10dd8000.bin"), "rb").read()
BASE = 0x4E102A4000
TEXT_LEN = 0x602000
ROD_OFF, ROD_LEN = 0x602000, 0x4E7000
DATAR_OFF, DATAR_LEN = 0xAE9000, 0x4B000
DATARW_OFF = 0xB34000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.skipdata = True

out = open(os.path.join(ROOT, "port", "semantic5.txt"), "w", encoding="utf-8")
def p(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    out.write(s + "\n")

def dis(off, count, label=""):
    p(f"--- {label} @ 0x{off:X}")
    n = 0
    for ins in md.disasm(text[off:off + count * 4], BASE + off):
        p(f"  +0x{ins.address - BASE:06X}: {ins.mnemonic:8s} {ins.op_str}")
        n += 1
        if n >= count: break

def word(off):
    return int.from_bytes(text[off:off + 4], "little")

def fn_start(off):
    o = off - 4
    while o > 0:
        w = word(o)
        if w == 0xD65F03C0 or w == 0x00000000:
            return o + 4
        o -= 4
    return 0

def rd_any(modoff):
    """Read u64 at a module offset from whichever dump covers it."""
    if DATAR_OFF <= modoff < DATAR_OFF + DATAR_LEN:
        return struct.unpack_from("<Q", datar, modoff - DATAR_OFF)[0]
    if ROD_OFF <= modoff < ROD_OFF + ROD_LEN:
        return struct.unpack_from("<Q", rod, modoff - ROD_OFF)[0]
    if DATARW_OFF <= modoff < DATARW_OFF + len(datarw):
        return struct.unpack_from("<Q", datarw, modoff - DATARW_OFF)[0]
    if 0 <= modoff < TEXT_LEN:
        return struct.unpack_from("<Q", text, modoff)[0]
    return None

def decode_thunk(stub):
    """PLT stub: adrp x16,page; ldr x17,[x16,#imm]; [add]; br x17 -> (slotModOff, value)."""
    ws = [word(stub + 4 * i) for i in range(4)]
    if (ws[0] & 0x9F00001F) != (0x90000000 | 16):
        return None, None
    immlo = (ws[0] >> 29) & 3
    immhi = (ws[0] >> 5) & 0x7FFFF
    simm = (immhi << 2) | immlo
    if simm & (1 << 20): simm -= 1 << 21
    page = (stub + BASE) & ~0xFFF
    page = ((page + (simm << 12)) - BASE) & 0xFFFFFFFFFFFFFFF
    if (ws[1] & 0xFFC003E0) != (0xF9400000 | (17 << 0) | (16 << 5)):
        return None, None
    imm12 = (ws[1] >> 10) & 0xFFF
    slot = page + imm * 8 if False else page + imm12 * 8
    return slot, rd_any(slot)

def resolve_b_target(boff):
    """b at module offset boff -> absolute module offset of target."""
    w = word(boff)
    if (w & 0xFC000000) != 0x14000000: return None
    imm = w & 0x3FFFFFF
    if imm & (1 << 25): imm -= 1 << 26
    return boff + (imm << 2)

# ============ A. nn::os wrapper region ============
dis(0x137040, (0x1372A0 - 0x137040) // 4, "A. wrapper region 0x137040..0x1372A0")

# ============ B. GOT targets ============
p("\n== B. GOT target disassembly")
for tgt in [0x57790, 0x6B000, 0x53880, 0x535E30, 0x50CFE0, 0x54C40, 0x541D0,
            0x54640, 0x545C0, 0x546A0, 0x54BC0, 0x45B80, 0x351E0, 0x4C080, 0x49BC0]:
    dis(tgt, 20, f"GOT target 0x{tgt:X}")

# ============ C. pthread family: ldrb [x,#0x40]; sub w,w,#3; cmp w,#1 ============
p("\n== C. pthread magic scan (ldrb w?,[x?,#0x40] + sub #3 + cmp #1)")
sites = []
o = 0
while o < TEXT_LEN - 16:
    w = word(o)
    # ldrb wt, [xn, #0x40]: 0x39400000 family, imm12 = 0x40
    if (w & 0xFFC003FF) == 0x39400000 or ((w & 0xFFC00000) == 0x39400000 and ((w >> 10) & 0xFFF) == 0x40):
        for k in range(1, 5):
            w2 = word(o + 4 * k)
            # sub wt, wn, #3 (32-bit imm12=3)
            if (w2 & 0xFF800000) == 0x51000000 and ((w2 >> 10) & 0xFFF) == 3:
                w3 = word(o + 4 * (k + 1))
                if (w3 & 0xFF80001F) == 0x7100001F and ((w3 >> 10) & 0xFFF) == 1:
                    sites.append(o)
                break
    o += 4
sites = sorted(set(sites))
p("sites:", [hex(s) for s in sites])
fns = {}
for s in sites:
    fns.setdefault(fn_start(s), []).append(s)
for f, ss in sorted(fns.items()):
    p(f"  fn 0x{f:X}  sites {[hex(s) for s in fns[f]]}")
    dis(f, 30, f"pthread-family fn 0x{f:X}")

# ============ D. posix_memalign candidates (cmp x1,#8 sites) ============
p("\n== D. cmp x1,#8 context")
for s in [0x121700, 0x1419e0, 0x141ae0, 0x1428a0, 0x1428f0, 0x512f5c, 0x5b72a8,
          0x5b7408, 0x5b80cc, 0x5b8628, 0x5b86d8, 0x5ca784, 0x5dc518]:
    f = fn_start(s)
    p(f"  site 0x{s:X} fn 0x{f:X}")
    dis(f, 26, f"cmp-x1-8 fn @ 0x{f:X}")

# ============ E. tpidr scan (fixed) ============
p("\n== E. mrs tpidr sites")
tp = []
for ins in md.disasm(text, BASE):
    if ins.mnemonic == "mrs" and "tpidr" in ins.op_str:
        tp.append((ins.address - BASE, ins.op_str))
p("total:", len(tp))
for o, s in tp:
    p(f"  0x{o:06X}: mrs {s}")
# disasm tiny leaf candidates (mrs then ret within ~5 instrs)
seen = set()
for o, s in tp:
    f = fn_start(o)
    if f in seen: continue
    seen.add(f)
    dis(f, 10, f"tpidr fn @ 0x{f:X}")

# ============ F. memcpy/memmove candidates ============
p("\n== F. mem-family candidates in [0x5224E0, 0x522B40]")
dis(0x5224E0, (0x522B80 - 0x5224E0) // 4, "mem region")

# ============ G. socket thunk table + fcntl/poll/errno ============
p("\n== G. thunk table 0x14D2E0..0x14D660 + GOT resolution")
o = 0x14D2E0
while o < 0x14D660:
    w = word(o)
    if (w & 0xFC000000) == 0x14000000:  # b
        tgt = resolve_b_target(o)
        slot, val = decode_thunk(tgt) if tgt else (None, None)
        vs = f"0x{val:X}" if isinstance(val, int) else str(val)
        inmod = f"in-module 0x{val - BASE:X}" if isinstance(val, int) and BASE <= val < BASE + TEXT_LEN else vs
        p(f"  thunk 0x{o:06X}: b 0x{tgt:X} slot {f'0x{slot:X}' if slot else '?'} -> {inmod}")
    else:
        p(f"  0x{o:06X}: word 0x{w:08X} (not b)")
    o += 4
for s in [0x14D560, 0x14D600, 0x91280, 0x14DE50]:
    dis(s, 36, f"fcntl candidate 0x{s:X}")

# ============ H. fsProxyGetter candidates ============
p("\n== H. fsProxyGetter candidates")
for s in [0xBD930, 0xBDC80, 0xBDF90, 0x1708F0]:
    dis(s, 30, f"fsProxyGetter cand 0x{s:X}")

# ============ I. mount family ============
p("\n== I. mount family")
for s in [0xD3430, 0xD3520, 0xD3610, 0xD39D0]:
    dis(s, 40, f"mount-family 0x{s:X}")

# ============ J. crc32 xref ============
p("\n== J. crc32 table xref (rodata 0x8DB228)")
def adrp_add_xrefs(target):
    """Find adrp+add pairs computing `target` (module offset)."""
    tpage = target & ~0xFFF
    tlo = target & 0xFFF
    hits = []
    for o in range(0, TEXT_LEN - 8, 4):
        w = word(o)
        if (w & 0x9F000000) != 0x90000000: continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        simm = (immhi << 2) | immlo
        if simm & (1 << 20): simm -= 1 << 21
        va = ((o + BASE) & ~0xFFF) + (simm << 12)
        if va != BASE + tpage: continue
        rd = w & 0x1F
        w2 = word(o + 4)
        if (w2 & 0xFFC00000) == 0x91000000 and (w2 & 0x1F) == rd and ((w2 >> 5) & 0x1F) == rd:
            if ((w2 >> 10) & 0xFFF) == tlo:
                hits.append(o)
    return hits
for h in adrp_add_xrefs(0x8DB228):
    f = fn_start(h)
    p(f"  xref at 0x{h:X}, fn 0x{f:X}")
    dis(f, 40, f"crc32 fn cand 0x{f:X}")

# ============ K. sha256 ============
p("\n== K. sha256 K-table xref (0x8C41C0) + init magic")
for h in adrp_add_xrefs(0x8C41C0):
    f = fn_start(h)
    p(f"  K xref at 0x{h:X}, fn 0x{f:X}")
# init: movz w?, #0xE667 (sha256 H6 low = 0xE667? actual: H = 6a09e667 bb67ae85 ...)
inits = []
for o in range(0, TEXT_LEN - 4, 4):
    w = word(o)
    if (w & 0xFFC00000) == 0x52800000:  # movz w
        imm16 = (w >> 5) & 0xFFFF
        if imm16 == 0xE667:
            inits.append(o)
p("movz w?,#0xE667 sites:", [hex(s) for s in inits])
for s in inits:
    f = fn_start(s)
    p(f"  init site 0x{s:X} fn 0x{f:X}")

# ============ L. longjmp ============
p("\n== L. longjmp candidate")
dis(0x5511B4, 20, "longjmp cand 0x5511B4")

# ============ M. thread create/exit/join cluster ============
p("\n== M. thread lifecycle cluster")
for label, site in [("create-retry cluster", 0x13DD14), ("exit (svcExitThread caller)", 0x13E0A8),
                    ("startThread caller", 0x13E0C4)]:
    f = fn_start(site)
    p(f"  {label}: site 0x{site:X} fn 0x{f:X}")
    dis(f, 16, f"fn head 0x{f:X}")
# enumerate function starts in the cluster region and their first BL
p("  -- cluster map 0x13DC00..0x13E600")
o = 0x13DC00
cur = fn_start(0x13DC00)
while o < 0x13E600:
    f = fn_start(o)
    if f != cur:
        cur = f
        # find first bl within 0x40 instrs
        blt = None
        for ins in md.disasm(text[f:f + 0x100], BASE + f):
            if ins.mnemonic == "bl":
                blt = ins.op_str; break
        p(f"  fn 0x{f:X} first-bl {blt}")
    o += 4

# ============ N. activity report ============
p("\n== N. activity report table search (fn 0x1C46B8)")
needle = struct.pack("<Q", BASE + 0x1C46B8)
for name, buf, baseoff in [("rodata", rod, ROD_OFF), ("datar", datar, DATAR_OFF), ("datarw", datarw, DATARW_OFF)]:
    at = 0
    while True:
        i = buf.find(needle, at)
        if i < 0: break
        p(f"  qword hit in {name} at module 0x{baseoff + i:X} -> table base 0x{baseoff + i - 0x120:X}")
        at = i + 1
dis(0x1C46B8, 24, "report fn 0x1C46B8")

# ============ P. romfs vtables (GetAttribute refs) ============
p("\n== P. vtables containing GetAttribute (BASE+0xA4214)")
needle = struct.pack("<Q", BASE + 0xA4214)
for name, buf, baseoff in [("rodata", rod, ROD_OFF), ("datar", datar, DATAR_OFF), ("datarw", datarw, DATARW_OFF)]:
    at = 0
    while True:
        i = buf.find(needle, at)
        if i < 0: break
        p(f"  GetAttribute ptr in {name} at module 0x{baseoff + i:X}")
        at = i + 1

# ============ Q. saveResult gadget verify ============
p("\n== Q. gadget byte verify")
sr = bytes.fromhex("600200b9f30b40f9fd7bc2a8c0035fd6")
sr64 = bytes.fromhex("600200f9f30b40f9fd7bc2a8c0035fd6")
for c in [0x28C980, 0x28D4D8, 0x4685A0]:
    p(f"  saveResult @0x{c:X}: {'MATCH' if text[c:c+16] == sr else 'no'}")
for c in [0x19BCC0, 0x19BFD4, 0x19BFEC, 0x19C108, 0x19CC00, 0x19CDC8]:
    p(f"  saveResult64 @0x{c:X}: {'MATCH' if text[c:c+16] == sr64 else 'no'}")

out.close()
print("done")
