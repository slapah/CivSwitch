#!/usr/bin/env python3
"""Pass 2: relaxed masked search (also mask ADD/SUB imm12, LDR/STR unsigned imm12,
MOVZ/MOVK/MOVN imm16) + semantic finders (errno, longjmp, crc32, sha256)."""
import json, os
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
words = np.frombuffer(text, dtype=np.uint32)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
BASE = 0x4E102A4000

def mask_pass2(w):
    if (w & 0xFC000000) in (0x94000000, 0x14000000):   # BL / B
        return 0xFC000000
    if (w & 0x7C000000) == 0x34000000:                 # CBZ/CBNZ
        return 0xFF00001F
    if (w & 0x7E000000) == 0x36000000:                 # TBZ/TBNZ
        return 0xFFF8001F
    if (w & 0xFF000010) == 0x54000000:                 # B.cond
        return 0xFF00001F
    if (w & 0x9F000000) == 0x90000000:                 # ADRP
        return 0x9F00001F
    if (w & 0x9F000000) == 0x10000000:                 # ADR
        return 0x9F00001F
    if (w & 0x3B000000) == 0x18000000:                 # LDR literal
        return 0xFC00001F
    if (w & 0x1F000000) == 0x11000000 and (w & 0x80000000) or \
       (w & 0x7F000000) == 0x11000000:                 # ADD/SUB immediate (32/64)
        return 0xFF200000 | 0x3E0 | 0x1F               # keep sf,op,S,Rn,Rd (drop sh,imm12)
    if (w & 0x3B000000) == 0x39000000:                 # LDR/STR unsigned immediate
        return 0xFFC00000 | 0x3E0 | 0x1F               # keep size,opc,Rn,Rt (drop imm12)
    if (w & 0x7F800000) in (0x52800000, 0x72800000, 0x12800000):  # MOVZ/MOVK/MOVN
        return 0xFF80001F
    return 0xFFFFFFFF

def find2(hexstr):
    pat = bytes.fromhex(hexstr)
    pat = pat[:len(pat) - len(pat) % 4]
    pw = np.frombuffer(pat, dtype=np.uint32)
    masks = np.array([mask_pass2(int(w)) for w in pw], dtype=np.uint32)
    n = len(words) - len(pw) + 1
    good = np.ones(n, dtype=bool)
    for j in range(len(pw)):
        good &= (words[j:j + n] & masks[j]) == (pw[j] & masks[j])
    return [int(i) * 4 for i in np.nonzero(good)[0]]

ENG = os.path.join(ROOT, "ns2jb-main", "engine")
def load(p):
    with open(os.path.join(ENG, p), encoding="utf-8") as f:
        return json.load(f)

sdk_functions = load("shared/sdk-functions.json")
sdk_layout = load("shared/sdk-layout.json")
thread_code = load("switch2/app/thread-code.json")["functions"]
event_code = load("switch2/app/event-code.json")["functions"]
hash_code = load("switch2/app/hash-code.json")
proxy_code = load("switch2/app/sdk-proxy-code.json")
cache_mount = load("switch2/memory/cache-mount-sdk.json")["functions"]
sched_ref = load("switch2/app/thread-scheduling-reference.json")["functions"]

todo = {
    "allocate": sdk_functions["allocate"]["bytes"],
    "fcntl": sdk_functions["fcntl"]["bytes"],
    "thread.create": thread_code["create"]["bytes"],
    "thread.join": thread_code["join"]["bytes"],
    "thread.exit": thread_code["exit"]["bytes"],
    "thread.call4": thread_code["call4"]["bytes"],
    "thread.tryWait": thread_code["tryWait"]["bytes"],
    "thread.tryWaitImplementation": thread_code["tryWaitImplementation"]["bytes"],
    "event.wait": event_code["wait"]["bytes"],
    "event.signal": event_code["signal"]["bytes"],
    "event.clear": event_code["clear"]["bytes"],
    "event.tryWait": event_code["tryWait"]["bytes"],
    "hash.GenerateSha256Hash": hash_code["bytes"],
    "proxy.fsProxyGetter": proxy_code["bytes"],
    "cacheMount.Unmount": cache_mount["Unmount"]["bytes"],
    "cacheMount.MountCache": cache_mount["MountCache"]["bytes"],
    "layout.vf0": sdk_layout["verifiedFunctions"][0]["bytes"],
    "layout.vf1": sdk_layout["verifiedFunctions"][1]["bytes"],
    "layout.vf2": sdk_layout["verifiedFunctions"][2]["bytes"],
    "layout.vf3": sdk_layout["verifiedFunctions"][3]["bytes"],
}
for n, e in sched_ref.items():
    todo["sched." + n] = e["bytes"]

for name, hexs in todo.items():
    hits = find2(hexs)
    print(f"{name:60s} {len(hits):3d} hits: {[hex(h) for h in hits[:8]]}")

# ---- longjmp semantic: sequence of ldp d8,d9 / d10,d11 / d12,d13 / d14,d15
print("\n== longjmp candidates (quad ldp d-regs)")
pat = bytes.fromhex('0824476d0a2c486d0c34496d0e3c4a6d')  # exact struct-offset variant
i = text.find(pat)
print("exact ldp d-reg quad:", hex(i) if i >= 0 else "MISS")
# looser: any 4 consecutive SIMD ldp post/unsigned on x0
cand = []
for off in range(0, len(text) - 64, 4):
    w0 = words[off // 4]
    if (w0 & 0x7F000000) != 0x6D000000:  # ldp simd unsigned-offset class
        continue
    seq = [words[off // 4 + k] for k in range(4)]
    if all((w & 0x7F000000) == 0x6D000000 for w in seq):
        cand.append(off)
print("quad-ldp-simd sites:", [hex(c) for c in cand[:20]])

# ---- errno: mrs xN, tpidr_el0; ... ; ret within 6 words
print("\n== errno candidates (mrs tpidr_el0 ... ret)")
cand = []
for off in range(0, len(text) - 40, 4):
    w = words[off // 4]
    if (w & 0xFFFFFFE0) == 0xD53BD040:  # mrs xN, tpidr_el0
        for k in range(1, 8):
            if words[off // 4 + k] == 0xD65F03C0:
                cand.append((off, k))
                break
print([hex(c[0]) for c in cand[:30]])

# ---- crc32 table in rodata
rod = open(os.path.join(ROOT, "dump", "4e108a6000.bin"), "rb").read()
i = rod.find(bytes.fromhex('96300772' if False else '96300777'))
print("\n== crc32 table at rodata file off:", hex(i) if i >= 0 else "MISS",
      "module off:", hex(0x602000 + i) if i >= 0 else "-")
# sha256 K table
i2 = rod.find(bytes.fromhex('982f8a4291443771'))
print("== sha256 K table at rodata file off:", hex(i2) if i2 >= 0 else "MISS",
      "module off:", hex(0x602000 + i2) if i2 >= 0 else "-")
