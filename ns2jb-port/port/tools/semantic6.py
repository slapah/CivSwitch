#!/usr/bin/env python3
# semantic6.py — decode thunks/GOT properly, resolve pending identifications
import json, struct, zlib, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BASE = 0x4E102A4000
SEGS = [  # (module_start, file, size)
    (0x000000, "dump/4e102a4000.bin", 0x602000),  # .text
    (0x602000, "dump/4e108a6000.bin", 0x4E7000),  # .rodata
    (0xAE9000, "dump/4e10d8d000.bin", 0x4B000),   # .data R
    (0xB34000, "dump/4e10dd8000.bin", 0x8000),    # .data RW truncated
]
_data = {}
for mstart, path, size in SEGS:
    with open(path, "rb") as f:
        _data[mstart] = f.read()

def read(moff, n):
    for mstart, _, size in SEGS:
        if mstart <= moff and moff + n <= mstart + size:
            return _data[mstart][moff - mstart: moff - mstart + n]
    return None

def qword(moff):
    b = read(moff, 8)
    return struct.unpack("<Q", b)[0] if b else None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

def disasm(moff, n_bytes):
    b = read(moff, n_bytes)
    if not b: return []
    return list(md.disasm(b, BASE + moff))

def decode_thunk(moff):
    """parse adrp x16,page; ldr x17,[x16,#imm]; br x17  (or add/br variants)"""
    ins = disasm(moff, 16)
    if len(ins) < 3: return None
    page = imm = None
    for i in ins:
        if i.mnemonic == "adrp":
            page = i.operands[1].imm - BASE
        elif i.mnemonic == "ldr" and page is not None:
            imm = i.operands[1].mem.disp
        elif i.mnemonic in ("br", "ret") and page is not None:
            slot = page + (imm or 0)
            val = qword(slot)
            tgt = (val - BASE) if (val is not None and BASE <= val < BASE + 0xC00000) else None
            return {"slot": slot, "val": val, "tgt": tgt}
        elif i.mnemonic == "b" and page is None:
            return {"direct_b": i.operands[0].imm - BASE}
    return None

def fn_head_around(moff, max_back=0x400):
    """scan backwards for a plausible function start (stp x29, x30 or sub sp) after a ret/b."""
    b = read(moff - max_back, max_back)
    if not b: return moff
    # find last word == ret (0xD65F03C0) or padding pattern before moff
    for i in range(max_back - 4, -1, -4):
        w = struct.unpack_from("<I", b, i)[0]
        if w in (0xD65F03C0,):
            return moff - max_back + i + 4
    return moff

def show(moff, n, label):
    print(f"--- {label} @ 0x{moff:X}")
    for i in disasm(moff, n):
        print(f"  +0x{i.address - BASE:X}: {i.mnemonic:8s} {i.op_str}")

out = open("port/semantic6.txt", "w")
sys.stdout = out

print("== A. thunk/GOT resolution")
thunks = {
    # wrappers' thunks
    0x5E4880: "lock (from SetThreadPriority wrapper)",
    0x5E48A0: "unlock",
    0x5E4F70: "SetThreadPriority impl thunk",
    0x5E4FA0: "wrapper 0x1370D0 (mov x1,x0)",
    0x5E4FB0: "wrapper 0x1370F0 (no-arg)",
    0x5E4FC0: "wrapper 0x137100 bare b (sleep?)",
    0x5E4FD0: "wrapper 0x137110 (mov x1,x0)",
    0x5E4FE0: "wrapper 0x137130 (mov x1,x0)",
    0x5E4FF0: "wrappers 0x137150+0x137160 (no-arg, ALIAS pair)",
    0x5E5010: "wrapper 0x1371A0 SetThreadCoreMask",
    0x5E5030: "wrapper 0x1371C0 GetThreadCoreMask",
    0x5E5040: "wrapper 0x1371E0 (no-arg)",
    0x5E5060: "wrapper 0x137200 GetSystemTick-ish",
    0x5E5090: "wrapper 0x137280 (mgr+0x3F0)",
    0x5E3A90: "memmove forward-copy tail",
    0x5E5550: "posix_memalign inner alloc",
    0x5E6580: "socket thunk table[0] @0x14D2F8",
    0x5E65D0: "fn 0x13E2E0/0x13E314 first-bl (impl thunks?)",
    0x5E3AD0: "misc first-bl thunk",
    0x5E6C50: "COMPAT IMPORT (pthread affinity mask AND)",
    0x5E86B0: "sleep thunk in create-retry loop",
}
# socket stubs
for a in [0x5EBB20,0x5EBB40,0x5EBB50,0x5EBB70,0x5EBB80,0x5EBBA0,0x5EBBB0,0x5EBBD0,0x5EBBE0,
          0x5EBC00,0x5EBC10,0x5EBC30,0x5EBC40,0x5EBC60,0x5EBC70,0x5EBC90,0x5EBCA0,0x5EBCC0,
          0x5EBCD0,0x5EBCF0,0x5EBD00,0x5EBD10,0x5EBD30,0x5EBD40,0x5EBD50,0x5EBD70,0x5EBD80,
          0x5EBD90,0x5EBDB0,0x5EBDC0,0x5EBDD0,0x5EBDE0,0x5EBDF0,0x5EBE00,0x5EBE10,0x5EBE30,
          0x5EBE40,0x5EBE60]:
    thunks[a] = f"socket stub 0x{a:X}"
for t in sorted(thunks):
    r = decode_thunk(t)
    if r is None:
        print(f"  thunk 0x{t:X} [{thunks[t]}]: decode FAILED")
        continue
    if "direct_b" in r:
        print(f"  thunk 0x{t:X} [{thunks[t]}]: direct b -> 0x{r['direct_b']:X}")
        continue
    slot, val, tgt = r["slot"], r["val"], r["tgt"]
    vs = f"0x{val:X}" if val is not None else "NOREAD"
    ts = f"-> in-module 0x{tgt:X}" if tgt is not None else ("-> EXTERNAL/zero" if val else "")
    print(f"  thunk 0x{t:X} [{thunks[t]}]: slot 0x{slot:X} val {vs} {ts}")

print()
print("== B. wrappers 0x137150/0x137160/0x137100/0x1370D0/0x137110/0x137130 full disasm")
for a in (0x1370D0, 0x1370F0, 0x137100, 0x137110, 0x137130, 0x137150, 0x137160, 0x1371E0, 0x137200, 0x137218, 0x137224):
    show(a, 0x30, f"wrapper 0x{a:X}")

print()
print("== C. pthread region disasm 0x1419E0..0x141E00 (getaffinity tail, setschedprio, getschedparam)")
show(0x1419E0, 0xF0, "pthread_getaffinity_np 0x1419E0 full")
b = read(0x141A00, 0x400)
for i in md.disasm(b, BASE + 0x141A00):
    pass
show(0x141AD0, 0x120, "pthread_setaffinity_np 0x141AD0")
# scan 0x141B98..0x142000 for magic shapes
print("--- scan 0x141B98..0x142000 for sub w8,w1,#5 / cmp w8,#0x1f / mov w9,#0x24 / bic")
for i in md.disasm(read(0x141B98, 0x468), BASE + 0x141B98):
    m, o = i.mnemonic, i.op_str
    if (m in ("sub","cmp","mov","bic","csel","csinc","b","bl","ret","stp","ldp","str","ldr","cbz","cbnz","adrp","add","ldrh","strh","ldrb","tbz","tbnz","mrs","ubfx","and","ands","ldur","stur","movk","nop","ldp","movz")) :
        mark = ""
        if m == "sub" and "#5" in o: mark = "  <== setschedprio magic?"
        if m == "cmp" and "#0x1f" in o: mark = "  <== cmp 0x1f"
        if m == "mov" and "#0x24" in o: mark = "  <== mov #0x24 (getschedparam)"
        if m == "bic" and "asr" in o: mark = "  <== bic asr (clamp)"
        if m == "bl": mark = "  <call>"
        if m == "ret": mark = "  <ret>"
        if mark or m in ("stp","sub") :
            print(f"  0x{i.address - BASE:X}: {m:8s} {o}{mark}")

print()
print("== D. posix_memalign 0x512F40 tail + free discovery")
show(0x512F40, 0x100, "posix_memalign full")

print()
print("== E. crc32 poly search + dump CRC")
poly_hits = []
tb = _data[0]
for off in range(0, len(tb) - 4, 4):
    w = struct.unpack_from("<I", tb, off)[0]
    if (w & 0xFFE00000) in (0x72A00000, 0x72C00000) and ((w >> 5) & 0xFFFF) == 0xEDB8:
        poly_hits.append(off)
print("  movk #0xEDB8 sites:", [hex(h) for h in poly_hits])
for h in poly_hits[:4]:
    head = fn_head_around(h, 0x200)
    print(f"  site 0x{h:X} fn_head~0x{head:X}")
crc = zlib.crc32(_data[0])
print(f"  zlib.crc32(.text 0x602000 bytes) = {crc} (0x{crc:08X})")

print()
print("== F. sha256 GenerateSha256Hash: BL callers of 0x529128 (init) and 0x117B0 (transform)")
callers_init, callers_tf = set(), set()
for off in range(0, len(tb) - 4, 4):
    w = struct.unpack_from("<I", tb, off)[0]
    if (w >> 26) == 0x25:  # BL
        imm = w & 0x3FFFFFF
        if imm & 0x2000000: imm -= 0x4000000
        tgt = off + imm * 4
        if tgt == 0x529128: callers_init.add(off)
        if tgt == 0x117B0: callers_tf.add(off)
print("  BL->init(0x529128) sites:", [hex(x) for x in sorted(callers_init)])
print("  BL->transform(0x117B0) sites:", [hex(x) for x in sorted(callers_tf)])
# fn head for each intersection-ish candidate: find fn containing both
def fn_of(site):
    return fn_head_around(site, 0x800)
init_fns = {}
for s in callers_init: init_fns.setdefault(fn_of(s), []).append(s)
tf_fns = {}
for s in callers_tf: tf_fns.setdefault(fn_of(s), []).append(s)
common = sorted(set(init_fns) & set(tf_fns))
print("  fns calling BOTH:", [hex(x) for x in common])
for c in common[:3]:
    show(c, 0x60, f"GenerateSha256Hash candidate 0x{c:X}")

print()
print("== G. fcntl impls 0x3FBE70/0x3FBE80/0x3FBE90 + 0x30B880")
for a in (0x3FBE70, 0x3FBE80, 0x3FBE90):
    show(a, 0x90, f"fcntl-impl cand 0x{a:X}")

print()
print("== H. fsProxyGetter init helpers")
for a in (0xBD9D0, 0xBDD20, 0xBE030):
    show(a, 0x90, f"proxy init 0x{a:X}")

print()
print("== I. mount family full bodies (find bss list anchor)")
for a in (0xD3430, 0xD3520, 0xD3610, 0xD39D0):
    show(a, 0x2C0, f"mount fn 0x{a:X}")

print()
print("== J. xref edges (from port/xref-index.json): callers of key fns")
try:
    xr = json.load(open("port/xref-index.json"))
except Exception as e:
    xr = None
    print("  xref-index.json load failed:", e)
if xr is not None:
    # figure out schema
    if isinstance(xr, dict):
        keys = list(xr.keys())[:5]
        print("  xref schema keys sample:", keys[:5])
        def callers_of(target):
            # support {'bl': {src:dst}} or list of [src,dst]
            res = []
            if "bl" in xr and isinstance(xr["bl"], dict):
                for s, d in xr["bl"].items():
                    if int(d) == target: res.append(int(s))
            elif "edges" in xr:
                for s, d in xr["edges"]:
                    if d == target: res.append(s)
            else:
                for k, v in xr.items():
                    if isinstance(v, list) and target in v: res.append(k)
            return res
    else:
        print("  xref is a list, len", len(xr), "sample", xr[:2])
        def callers_of(target):
            return [e[0] for e in xr if isinstance(e, (list, tuple)) and len(e) >= 2 and e[1] == target]
    for name, tgt in [("svcExitThread 0x168B4C", 0x168B4C),
                      ("CloseHandle helper 0x13E5BC", 0x13E5BC),
                      ("svcWaitSync wrapper 0x168BF4", 0x168BF4),
                      ("errno cand 0x5515F0", 0x5515F0),
                      ("errno cand 0x551600", 0x551600),
                      ("impl WaitThread 0x13E2E8", 0x13E2E8),
                      ("impl TryWaitThread 0x13E31C", 0x13E31C),
                      ("create fn 0x13DCC4", 0x13DCC4),
                      ("svcCreateThread wrapper 0x168B2C", 0x168B2C)]:
        try:
            cs = callers_of(tgt)
            cs = [int(c) if not isinstance(c, int) else c for c in cs]
            print(f"  callers of {name}: {[hex(c & 0xFFFFFF) for c in cs][:20]}")
        except Exception as e:
            print(f"  callers of {name}: ERROR {e}")

print()
print("== K. activity table xref: adrp page 0xAFF000 refs")
# find adrp with page == 0xAFF000
for off in range(0, len(tb) - 4, 4):
    w = struct.unpack_from("<I", tb, off)[0]
    if (w & 0x9F00001F) == (0x90000000 | ((0xAFF000 >> 12) & 0x3) << 29) or True:
        pass
# simpler: decode all adrp via capstone would be slow; compute encoding
# adrp: immlo bits30-29, immhi bits23-5; page_rel = (pc&~0xFFF) + (imm<<12)
hits = []
for off in range(0, len(tb) - 4, 4):
    w = struct.unpack_from("<I", tb, off)[0]
    if (w & 0x9F000000) != 0x90000000: continue
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    pc = off
    page = (pc & ~0xFFF) + (imm << 12)
    if page == 0xAFF000:
        hits.append(off)
print("  adrp 0xAFF000 sites:", [hex(h) for h in hits])

print()
print("== L. fcntl wrapper trio relationship: which wrapper is exported fcntl? xref 0x14D560/0x14D600/0x14DE50 callers")
# find BL sites to each
for tgt in (0x14D560, 0x14D600, 0x14DE50, 0x91280):
    n = 0
    for off in range(0, len(tb) - 4, 4):
        w = struct.unpack_from("<I", tb, off)[0]
        if (w >> 26) == 0x25:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000: imm -= 0x4000000
            if off + imm * 4 == tgt: n += 1
    print(f"  BL -> 0x{tgt:X}: {n} sites")

print()
print("== M. errno region quick disasm 0x5515F0..0x551620")
show(0x5515F0, 0x20, "errno cand A 0x5515F0")
show(0x551600, 0x20, "errno cand B 0x551600")

out.close()
print("done", file=sys.stderr)
