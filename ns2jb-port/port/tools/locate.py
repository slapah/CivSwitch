#!/usr/bin/env python3
"""Workstream B: locate ns2jb-required symbols in the Civ7 nnSdk dump.

Reads ns2jb-main/engine JSONs (SmileBASIC offsets + expected bytes) and
searches dump/4e102a4000.bin (Civ7 sdk .text) with position-aware masking:
branch immediates, ADRP/ADR immediates, LDR-literal and cond-branch offsets
are wildcarded because Civ7's sdk is a different build/layout.
"""
import json, os, re, struct, sys
import numpy as np

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
TEXT_PATH = os.path.join(ROOT, "dump", "4e102a4000.bin")
TEXT_BASE = 0x4E102A4000          # runtime base in dump session (file offset == module offset)
RODATA_OFF = 0x602000             # module offset where .rodata file starts
DATAR_OFF = 0xAE9000
DATARW_OFF = 0xB34000

text = np.fromfile(TEXT_PATH := TEXT_PATH, dtype=np.uint8)
words = np.frombuffer(text.tobytes(), dtype=np.uint32)

def word_mask(w):
    """Mask keeping only position-independent bits of instruction w."""
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
    return 0xFFFFFFFF

def word_mask_relaxed(w):
    m = word_mask(w)
    if m != 0xFFFFFFFF:
        return m
    if (w & 0x7F800000) in (0x52800000, 0x72800000, 0x12800000):  # MOVZ/MOVK/MOVN
        return 0xFF80001F                          # drop imm16
    return m

def find_pattern(hexstr, relaxed=False, require_words=0):
    pat = bytes.fromhex(hexstr)
    if len(pat) % 4:
        pat = pat[:len(pat) - len(pat) % 4]
    pw = np.frombuffer(pat, dtype=np.uint32)
    maskf = word_mask_relaxed if relaxed else word_mask
    masks = np.array([maskf(int(w)) for w in pw], dtype=np.uint32)
    n = len(words) - len(pw) + 1
    good = np.ones(n, dtype=bool)
    for j in range(len(pw)):
        good &= (words[j:j + n] & masks[j]) == (pw[j] & masks[j])
    return [int(i) * 4 for i in np.nonzero(good)[0]]

def find_exact(hexstr):
    pat = bytes.fromhex(hexstr)
    out, at = [], 0
    while True:
        i = text.tobytes().find(pat, at)
        if i < 0:
            return out
        out.append(i); at = i + 1

def hx(v):
    return f"0x{v:X}"

# ---------------------------------------------------------------- patterns
ENG = os.path.join(ROOT, "ns2jb-main", "engine")

def load(p):
    with open(os.path.join(ENG, p), encoding="utf-8") as f:
        return json.load(f)

sdk_functions = load("shared/sdk-functions.json")
sdk_layout = load("shared/sdk-layout.json")
thread_code = load("switch2/app/thread-code.json")["functions"]
event_code = load("switch2/app/event-code.json")["functions"]
timing_code = load("switch2/app/timing-code.json")["functions"]
hash_code = load("switch2/app/hash-code.json")
proxy_code = load("switch2/app/sdk-proxy-code.json")
cache_mount = load("switch2/memory/cache-mount-sdk.json")["functions"]
sched_ref = load("switch2/app/thread-scheduling-reference.json")["functions"]
compat_ref = load("switch2/app/compat-affinity-reference.json")

patterns = {}   # name -> dict(smile=..., hex=..., src=...)
for name, e in sdk_functions.items():
    patterns[f"sdk-functions.{name}"] = dict(smile=e["offset"], hex=e["bytes"],
                                             src="shared/sdk-functions.json")
patterns["inline.memcpy"] = dict(smile=0x586FB0, src="probe-reserved-gap.cjs:186",
    hex='e80301cb090940923f0102eb22040054a90700b4ea0301aaeb0300aaa8091037280a0837680000364801403968010039420009cb0800098b2100098b1f0940f2')
patterns["inline.svcQueryMemory"] = dict(smile=0x158314, src="native.cjs:84 + contract",
    hex='e11f0ff8c10000d4e20340f9410000b9ff430091')  # contract shape words, LE
patterns["inline.activityReport"] = dict(smile=0x1B18A0, src="lib/qualify.cjs:31",
    hex='0020009121088052e6401014')
for name, e in thread_code.items():
    patterns[f"thread.{name}"] = dict(smile=e["offset"], hex=e["bytes"], src="app/thread-code.json")
for name, e in event_code.items():
    patterns[f"event.{name}"] = dict(smile=e["offset"], hex=e["bytes"], src="app/event-code.json")
for name, e in timing_code.items():
    patterns[f"timing.{name}"] = dict(smile=e["offset"], hex=e["bytes"], src="app/timing-code.json")
patterns["hash.GenerateSha256Hash"] = dict(smile=hash_code["offset"], hex=hash_code["bytes"],
                                           src="app/hash-code.json")
patterns["proxy.fsProxyGetter"] = dict(smile=proxy_code["functionOffset"], hex=proxy_code["bytes"],
                                       src="app/sdk-proxy-code.json")
for name, e in cache_mount.items():
    patterns[f"cacheMount.{name}"] = dict(smile=e["offset"], hex=e["bytes"],
                                          src="memory/cache-mount-sdk.json")
for name, e in sched_ref.items():
    patterns[f"sched.{name}"] = dict(smile=e["offset"], hex=e["bytes"],
                                     src="app/thread-scheduling-reference.json")
patterns["compat.importStub"] = dict(smile=compat_ref["import"]["offset"],
                                     hex=compat_ref["import"]["bytes"],
                                     src="app/compat-affinity-reference.json#import")
for i, e in enumerate(sdk_layout["verifiedFunctions"]):
    patterns[f"layout.verifiedFunction{i}"] = dict(smile=e["offset"], hex=e["bytes"],
                                                   src="shared/sdk-layout.json")
# svc leaf wrappers from ro/control.cjs and worker-control.cjs
patterns["svc.signalEvent(0x11)"] = dict(smile=None, hex='210200d4c0035fd6', src="ro/control.cjs:41")
patterns["svc.clearEvent(0x12)"] = dict(smile=None, hex='410200d4c0035fd6', src="ro/control.cjs:41")
patterns["svc.cancelSynchronization(0x19)"] = dict(smile=0x158414, hex='210300d4c0035fd6',
                                                   src="ro/worker-control.cjs:4")
patterns["svc.getThreadId(0x25)"] = dict(smile=0x15847C,
    hex='e00f1ff8a10400d4e20340f9410000f9ff430091c0035fd6', src="ro/control.cjs:207")
patterns["svc.waitForAddress(0x18)"] = dict(smile=0x1583FC,
    hex='e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6', src="ro/control.cjs:208")
patterns["svc.getInfo(0x29)"] = dict(smile=0x1584AC,
    hex='e00f1ff8210500d4e20340f9410000f9ff430091c0035fd6', src="ro/control.cjs:209")
# timing.cjs nativeFrequencyCode lives in another module; search anyway
patterns["other.nativeFrequency"] = dict(smile=0x13D6F0, hex='00ca9a52803ba072c0035fd6',
                                         src="app/timing.cjs:6 (module: compat, not sdk)")

results = {}
for name, p in patterns.items():
    hits = find_exact(p["hex"])
    method = "exact"
    if not hits:
        hits = find_pattern(p["hex"])
        method = "masked"
    if not hits:
        hits = find_pattern(p["hex"], relaxed=True)
        method = "masked-relaxed"
    results[name] = dict(smile=p["smile"], src=p["src"], method=method if hits else "MISSING",
                         civ7=[hx(h) for h in hits])

with open(os.path.join(ROOT, "port", "pattern-search-results.json"), "w") as f:
    json.dump(results, f, indent=2)

for name, r in results.items():
    sm = hx(r["smile"]) if r["smile"] is not None else "-"
    print(f"{name:55s} smile={sm:10s} {r['method']:14s} {r['civ7'][:6]}")
