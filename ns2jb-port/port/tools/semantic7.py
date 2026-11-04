#!/usr/bin/env python3
# semantic7.py — vtable slot mapping, fcntl/errno/free/poll/sha256/crc32/join/exit/create
import json, struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BASE = 0x4E102A4000
SEGS = [(0x000000, "dump/4e102a4000.bin", 0x602000),
        (0x602000, "dump/4e108a6000.bin", 0x4E7000),
        (0xAE9000, "dump/4e10d8d000.bin", 0x4B000),
        (0xB34000, "dump/4e10dd8000.bin", 0x8000)]
_data = {}
for mstart, path, size in SEGS:
    with open(path, "rb") as f: _data[mstart] = f.read()
def read(moff, n):
    for mstart, _, size in SEGS:
        if mstart <= moff and moff + n <= mstart + size:
            return _data[mstart][moff - mstart: moff - mstart + n]
    return None
def qword(moff):
    b = read(moff, 8)
    return struct.unpack("<Q", b)[0] if b else None
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
def disasm(moff, n):
    b = read(moff, n)
    return list(md.disasm(b, BASE + moff)) if b else []
def show(moff, n, label):
    print(f"--- {label} @ 0x{moff:X}")
    for i in disasm(moff, n):
        print(f"  +0x{i.address - BASE:X}: {i.mnemonic:8s} {i.op_str}")
def decode_thunk(moff):
    ins = disasm(moff, 16)
    page = imm = None
    for i in ins:
        if i.mnemonic == "adrp": page = i.operands[1].imm - BASE
        elif i.mnemonic == "ldr" and page is not None: imm = i.operands[1].mem.disp
        elif i.mnemonic in ("br", "ret") and page is not None:
            slot = page + (imm or 0); val = qword(slot)
            tgt = (val - BASE) if (val is not None and BASE <= val < BASE + 0xC00000) else None
            return slot, val, tgt
        elif i.mnemonic == "b" and page is None:
            return None, None, i.operands[0].imm - BASE
    return None, None, None
def bl_sites(target):
    tb = _data[0]; hits = []
    for off in range(0, len(tb) - 4, 4):
        w = struct.unpack_from("<I", tb, off)[0]
        if (w >> 26) == 0x25:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000: imm -= 0x4000000
            if off + imm * 4 == target: hits.append(off)
    return hits
def fn_head_around(moff, max_back=0x600):
    b = read(moff - max_back, max_back)
    if not b: return moff
    for i in range(max_back - 4, -1, -4):
        if struct.unpack_from("<I", b, i)[0] == 0xD65F03C0:
            return moff - max_back + i + 4
    return moff
def scan_dataq(target_abs):
    """find qword == target_abs in rodata/.data R"""
    hits = []
    for mstart, _, size in SEGS[1:3]:
        d = _data[mstart]
        p = struct.pack("<Q", target_abs)
        i = d.find(p)
        while i >= 0:
            hits.append(mstart + i); i = d.find(p, i + 8)
    return hits

out = open("port/semantic7.txt", "w"); sys.stdout = out

print("== A. ThreadManager vtable: find qword BASE+0x13E274 (SetThreadPriority impl)")
vt_hits = scan_dataq(BASE + 0x13E274)
print("  vtable candidate addrs:", [hex(h) for h in vt_hits])
for vt in vt_hits:
    # walk back to table start (stop at non-code-ptr), then enumerate
    start = vt
    while True:
        v = qword(start - 16)  # skip one (may be RTTI/name ptr)
        if v is None or not (BASE <= v < BASE + 0x602000):
            break
        start -= 8
    # try start-8 (last slot may still be code)
    print(f"  vtable region around 0x{vt:X}:")
    for a in range(start - 8, vt + 0x60, 8):
        v = qword(a)
        tag = ""
        if v is not None and BASE <= v < BASE + 0x602000:
            mo = v - BASE
            known = {0x13E274:"SetThreadPriority",0x13E2AC:"GetThreadPriority",0x13E2E8:"WaitThread?",
                     0x13E31C:"TryWaitThread?",0x13E3E8:"GetCurrentCoreNumber",0x13E3EC:"SetThreadCoreMask",
                     0x13E424:"GetThreadCoreMask",0x13E484:"GetThreadAvailableCoreMask",0x13E5BC:"CloseHandle?",0x13E5EC:"ClearEvent?"}
            tag = known.get(mo, "")
            print(f"    [+0x{a - start:3X}] 0x{a:X} -> 0x{mo:X} {tag}")
        else:
            print(f"    [+0x{a - start:3X}] 0x{a:X} -> {'None' if v is None else hex(v)} (non-code)")

print()
print("== B. glue targets from wrapper thunks (identify via vtable slot ldr)")
for name, t in [("0x1370D0->",0x57790),("0x1370F0->",0x6B000),("0x137100 sleep->",0x53880),
                ("0x137110->",0x535E30),("0x137130->",0x50CFE0),("0x137150/60->",0x54C40),
                ("0x1371A0 SetCoreMask->",0x541D0),("0x1371C0 GetCoreMask->",0x54640),
                ("0x1371E0->",0x545C0),("0x137200->",0x546A0),("0x137280->",0x54BC0),
                ("SetThreadPrio impl glue",0x56310),("lock",0x45B80),("unlock",0x351E0)]:
    show(t, 0x40, f"glue {name} 0x{t:X}")

print()
print("== C. fcntl/ioctl thunks after socket stubs")
for t in (0x5EBE70, 0x5EBE80, 0x5EBE90, 0x5EB7B0, 0x5E5550):
    slot, val, tgt = decode_thunk(t)
    print(f"  thunk 0x{t:X}: slot {hex(slot) if slot else '?'} val {hex(val) if val else '?'} -> {hex(tgt) if tgt is not None else 'EXT'}")
for name, a in [("fcntl cand (from 0x14D560 via 0x5EBE70)", decode_thunk(0x5EBE70)[2]),
                ("ioctl? cand (from 0x14DE50 via 0x5EBE80)", decode_thunk(0x5EBE80)[2]),
                ("cand (from 0x14D600 via 0x5EBE90)", decode_thunk(0x5EBE90)[2])]:
    if a: show(a, 0x90, name + f" 0x{a:X}")

print()
print("== D. errno: disasm 0x50B2E0 (thunk 0x5E5550 target, used by posix_memalign)")
show(0x50B2E0, 0x30, "errno? 0x50B2E0")
print("  BL->0x50B2E0 count:", len(bl_sites(0x50B2E0)))
print("  BL->0x5515F0 count:", len(bl_sites(0x5515F0)), " BL->0x551600 count:", len(bl_sites(0x551600)))
# who calls the socket-region targets? check BL from 0x14C000..0x14E000 to each errno cand
tb = _data[0]
for name, tgt in [("0x50B2E0",0x50B2E0),("0x5515F0",0x5515F0),("0x551600",0x551600)]:
    n = 0
    for off in range(0x14C000, 0x14E000, 4):
        w = struct.unpack_from("<I", tb, off)[0]
        if (w >> 26) == 0x25:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000: imm -= 0x4000000
            if off + imm * 4 == tgt: n += 1
    print(f"  BL from socket region -> {name}: {n}")

print()
print("== E. free: memalign internal + cluster scan")
slot, val, tgt = decode_thunk(0x5EB7B0)
print(f"  thunk 0x5EB7B0 (posix_memalign's memalign) -> {hex(tgt) if tgt else val}")
if tgt:
    show(tgt, 0x60, f"memalign internal 0x{tgt:X}")
    # scan +-0x1000 for fn heads with cbz x0 early + page-mask and
    lo, hi = max(0, tgt - 0x1800), tgt + 0x1800
    heads = []
    for off in range(lo, hi, 4):
        w = struct.unpack_from("<I", tb, off)[0]
        if w == 0xD65F03C0 and off + 4 < hi:
            heads.append(off + 4)
    for h in heads:
        ins = disasm(h, 0x30)
        txt = " ; ".join(f"{i.mnemonic} {i.op_str}" for i in ins[:8])
        if any("cbz" in i.mnemonic and "x0" in i.op_str for i in ins[:6]) and any("0xffffffffffff" in i.op_str for i in ins):
            print(f"  free candidate 0x{h:X}: {txt}")

print()
print("== F. sha256: GOT slots pointing to init 0x529128 / transform 0x117B0")
for tname, t in [("init",0x529128),("transform",0x117B0)]:
    hits = scan_dataq(BASE + t)
    print(f"  qword BASE+0x{t:X} at: {[hex(h) for h in hits]}")
    for h in hits:
        # find stub (adrp page of h) — stubs live in .text; find adrp+ldr referencing h
        page = h & ~0xFFF; imm = h - page
        # scan .text for adrp page then ldr imm pattern within 8 bytes — brute: check thunks in known stub area 0x5E3000..0x5EC000
        for s in range(0x5E3000, 0x5EC000, 4):
            w = struct.unpack_from("<I", tb, s)[0]
            if (w & 0x9F000000) != 0x90000000: continue
            immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF; ii=(immhi<<2)|immlo
            if ii & (1<<20): ii -= (1<<21)
            if (s & ~0xFFF) + (ii<<12) != page: continue
            w2 = struct.unpack_from("<I", tb, s+4)[0]
            # ldr x17,[x16,#imm]: 0xF9400211-ish; check imm12 field
            if (w2 & 0xFFC00000) != 0xF9400000: continue
            if ((w2 >> 10) & 0xFFF) * 8 != imm: continue
            bls = bl_sites(s)
            print(f"    stub 0x{s:X} (slot 0x{h:X}), BL sites: {[hex(b) for b in bls][:8]}")
            for bsite in bls[:4]:
                print(f"      in fn ~0x{fn_head_around(bsite):X}")

print()
print("== G. crc32 cluster disasm (find zlib crc32(crc,buf,len))")
for h in (0x72C24, 0x72ED8, 0x73028, 0x730F8, 0x731B0):
    show(h, 0x60, f"crc fn 0x{h:X}")

print()
print("== H. join/exit/create via BL sites")
for name, t in [("svcExitThread wrapper 0x168B4C",0x168B4C),
                ("svcWaitSync wrapper 0x168BF4",0x168BF4),
                ("CloseHandle helper 0x13E5BC",0x13E5BC),
                ("create fn 0x13DCC4",0x13DCC4),
                ("svcCreateThread wrapper 0x168B2C",0x168B2C),
                ("svcStartThread wrapper 0x168B44",0x168B44),
                ("svcGetThreadId wrapper 0x168C74",0x168C74)]:
    sites = bl_sites(t)
    fns = {}
    for s in sites: fns.setdefault(fn_head_around(s), []).append(s)
    print(f"  BL->{name}: {len(sites)} sites in fns: " + ", ".join(f"0x{f:X}({len(v)})" for f, v in sorted(fns.items())[:12]))

print()
print("== I. poll identification: disasm unknown socket-stub targets (find nfds loop)")
for stub, tgt in [(0x5EBB20,0x152DE0),(0x5EBB50,0x1531C0),(0x5EBB70,0x1533F0),(0x5EBBA0,0x1543A0),
                  (0x5EBBB0,0x154590),(0x5EBBD0,0x1547B0),(0x5EBBE0,0x154F70),(0x5EBC10,0x155350),
                  (0x5EBC60,0x155890),(0x5EBC70,0x155A50),(0x5EBC90,0x155C00),(0x5EBCA0,0x155DB0),
                  (0x5EBCD0,0x156120),(0x5EBCF0,0x1562E0),(0x5EBD10,0x1569D0),(0x5EBD40,0x157570),
                  (0x5EBD50,0x156D60),(0x5EBD70,0x156ED0),(0x5EBD80,0x157040),(0x5EBD90,0x158860),
                  (0x5EBDC0,0x158B40),(0x5EBDD0,0x158CB0),(0x5EBDE0,0x1571B0),(0x5EBDF0,0x157390),
                  (0x5EBE10,0x157850),(0x5EBE30,0x157A70),(0x5EBE40,0x158480),(0x5EBE60,0x158670)]:
    ins = disasm(tgt, 0x20)
    head = " ; ".join(f"{i.mnemonic} {i.op_str}" for i in ins[:5])
    print(f"  stub 0x{stub:X} -> 0x{tgt:X}: {head}")

print()
print("== J. mount-table: adrp->data/bss refs in fns 0xD3000..0xD6000")
for off in range(0xD3000, 0xD6000, 4):
    w = struct.unpack_from("<I", tb, off)[0]
    if (w & 0x9F000000) != 0x90000000: continue
    immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF; ii=(immhi<<2)|immlo
    if ii & (1<<20): ii -= (1<<21)
    page = (off & ~0xFFF) + (ii<<12)
    if page >= 0xAE9000:  # data/bss region refs only
        w2 = struct.unpack_from("<I", tb, off+4)[0]
        extra = ""
        if (w2 & 0xFFC00000) == 0xF9400000:  # ldr x
            extra = f" ldr [x{(w2&0x1F)},#{(w2>>10)&0xFFF*8}]" 
            imm12 = ((w2 >> 10) & 0xFFF) * 8
            extra = f" ldr #{imm12:#x} -> {page+imm12:#x}"
        elif (w2 & 0xFFC00000) == 0xF9000000:
            imm12 = ((w2 >> 10) & 0xFFF) * 8
            extra = f" str #{imm12:#x} -> {page+imm12:#x}"
        elif (w2 & 0xFFC00000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            extra = f" add #{imm12:#x} -> {page+imm12:#x}"
        print(f"  0x{off:X}: adrp page {page:#x}{extra}")

print()
print("== K. rodata strings at proxy-init refs: 0x8E20CC and 0x8E2680")
for a in (0x8E20CC, 0x8E2680, 0x8EB3E0):
    b = read(a, 64)
    if b:
        s = b.split(b"\0")[0]
        print(f"  0x{a:X}: {s!r}")

out.close(); print("done", file=sys.stderr)
