#!/usr/bin/env python3
"""Pass 3: corrected ADD/SUB-immediate mask (drop all 12 bits)."""
import json, os
import numpy as np

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
words = np.frombuffer(text, dtype=np.uint32)

def mask3(w):
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
    if (w & 0x7F000000) == 0x11000000:          # ADD/SUB imm (32+64)
        return 0xFFC003FF
    if (w & 0x3B000000) == 0x39000000:          # LDR/STR unsigned imm
        return 0xFFC003FF
    if (w & 0x7F800000) in (0x52800000, 0x72800000, 0x12800000):
        return 0xFF80001F
    return 0xFFFFFFFF

def find3(hexstr):
    pat = bytes.fromhex(hexstr)
    pat = pat[:len(pat) - len(pat) % 4]
    pw = np.frombuffer(pat, dtype=np.uint32)
    masks = np.array([mask3(int(w)) for w in pw], dtype=np.uint32)
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
    hits = find3(hexs)
    print(f"{name:60s} {len(hits):3d} hits: {[hex(h) for h in hits[:10]]}")
