#!/usr/bin/env python3
"""Diagnose partial matches: longest masked-prefix match anywhere in Civ7 text."""
import json, os
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
words = np.frombuffer(text, dtype=np.uint32)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
BASE = 0x4E102A4000

def mask_pass2(w):
    if (w & 0xFC000000) in (0x94000000, 0x14000000):
        return 0xFC000000
    if (w & 0x7C000000) == 0x34000000:
        return 0xFF00001F
    if (w & 0x7E000000) == 0x36000000:
        return 0xFFF8001F
    if (w & 0xFF000010) == 0x54000000:
        return 0xFF00001F
    if (w & 0x9F000000) in (0x90000000, 0x10000000):
        return 0x9F00001F
    if (w & 0x3B000000) == 0x18000000:
        return 0xFC00001F
    if (w & 0x7F000000) == 0x11000000:
        return 0xFF2003FF
    if (w & 0x3B000000) == 0x39000000:
        return 0xFFC003FF
    if (w & 0x7F800000) in (0x52800000, 0x72800000, 0x12800000):
        return 0xFF80001F
    return 0xFFFFFFFF

def diagnose(name, hexstr, minscore=6):
    pat = bytes.fromhex(hexstr)
    pat = pat[:len(pat) - len(pat) % 4]
    pw = np.frombuffer(pat, dtype=np.uint32)
    masks = np.array([mask_pass2(int(w)) for w in pw], dtype=np.uint32)
    n = len(words) - len(pw) + 1
    failat = np.full(n, len(pw), dtype=np.int32)
    for j in range(len(pw)):
        bad = (words[j:j + n] & masks[j]) != (pw[j] & masks[j])
        failat[(failat == len(pw)) & bad] = j
    best = np.max(failat)
    pos = np.nonzero(failat == best)[0][:4]
    print(f"{name:40s} patWords={len(pw):3d} bestPrefix={best:3d} at {[hex(int(p)*4) for p in pos]}")
    if best < len(pw):
        j = best
        ins_p = next(md.disasm(pw[j:j+1].tobytes(), 0))
        ins_t = next(md.disasm(words[int(pos[0])+j:int(pos[0])+j+1].tobytes(), 0))
        print(f"    first diff word {j}: pattern {ins_p.mnemonic} {ins_p.op_str}  vs  text {ins_t.mnemonic} {ins_t.op_str}")

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

todo = [
    ("allocate", sdk_functions["allocate"]["bytes"]),
    ("fcntl", sdk_functions["fcntl"]["bytes"]),
    ("thread.create", thread_code["create"]["bytes"]),
    ("thread.join", thread_code["join"]["bytes"]),
    ("thread.exit", thread_code["exit"]["bytes"]),
    ("thread.tryWaitImplementation", thread_code["tryWaitImplementation"]["bytes"]),
    ("event.wait", event_code["wait"]["bytes"]),
    ("event.signal", event_code["signal"]["bytes"]),
    ("event.clear", event_code["clear"]["bytes"]),
    ("event.tryWait", event_code["tryWait"]["bytes"]),
    ("hash.GenerateSha256Hash", hash_code["bytes"]),
    ("proxy.fsProxyGetter", proxy_code["bytes"]),
    ("cacheMount.Unmount", cache_mount["Unmount"]["bytes"]),
    ("cacheMount.MountCache", cache_mount["MountCache"]["bytes"]),
    ("layout.vf1", sdk_layout["verifiedFunctions"][1]["bytes"]),
    ("layout.vf2", sdk_layout["verifiedFunctions"][2]["bytes"]),
    ("layout.vf3", sdk_layout["verifiedFunctions"][3]["bytes"]),
    ("sched.pthread_getaffinity_np", sched_ref["pthread_getaffinity_np"]["bytes"]),
    ("sched.pthread_setaffinity_np", sched_ref["pthread_setaffinity_np"]["bytes"]),
    ("sched.pthread_getschedparam", sched_ref["pthread_getschedparam"]["bytes"]),
    ("sched.pthread_setschedprio", sched_ref["pthread_setschedprio"]["bytes"]),
]
for name, hexs in todo:
    diagnose(name, hexs)
