#!/usr/bin/env python3
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_BASE = 0x4E102A4000
TEXT_SHA256 = "afaa7c04bffe9f269f5e87b7188da789ab5e59bc87a74acce10c1874432452c3"
EXPECTED_FUNCTIONS = {
    "Unmount": (0xA4B70, 0x148, "_ZN2nn2fs6detail7UnmountEPKc"),
    "MountCache": (0xDF6B0, 0x13C, "_ZN2nn2fs17MountCacheStorageEPKci"),
    "GetAttribute": (0xA4214, 0x20, "_ZNK2nn2fs6detail18FileSystemAccessor20GetSaveDataAttributeEPNS0_17SaveDataAttributeE"),
}
SVC_WRAPPERS = {
    "svcCancelSynchronization": (0x168C0C, "210300d4c0035fd6"),
    "event-signal": (0x168BAC, "210200d4c0035fd6"),
    "event-clear": (0x168BB4, "410200d4c0035fd6"),
    "svcGetThreadId": (0x168C74, "e00f1ff8a10400d4e20340f9410000f9ff430091c0035fd6"),
    "svcWaitForAddress": (0x168BF4, "e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6"),
    "svcGetInfo": (0x168CA4, "e00f1ff8210500d4e20340f9410000f9ff430091c0035fd6"),
}

text = (ROOT / "dump/4e102a4000.bin").read_bytes()
data_r = (ROOT / "dump/4e10d8d000.bin").read_bytes()
config = json.loads((ROOT / "port/civ7-app/cache-mount-sdk.json").read_text(encoding="utf-8"))
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def adrp_add_xrefs(target):
    hits = []
    for offset in range(0, len(text) - 20, 4):
        word = struct.unpack_from("<I", text, offset)[0]
        if word & 0x9F000000 != 0x90000000:
            continue
        immediate = ((word >> 3) & 0x1FFFFC) | ((word >> 29) & 3)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        if (offset & ~0xFFF) + (immediate << 12) != (target & ~0xFFF):
            continue
        register = word & 31
        for following in range(offset + 4, offset + 24, 4):
            add = struct.unpack_from("<I", text, following)[0]
            if (add & 0xFFC00000 == 0x91000000 and add & 31 == register and
                    (add >> 5) & 31 == register and ((add >> 10) & 0xFFF) == (target & 0xFFF)):
                hits.append(offset)
    return hits


check(len(text) == 0x602000, "Civ7 text dump length differs")
check(hashlib.sha256(text).hexdigest() == TEXT_SHA256 == config["sha256"], "Civ7 text SHA-256 differs")
check(config["base"] == hex(TEXT_BASE), "Cache-mount dump base differs")
check(set(config["functions"]) == set(EXPECTED_FUNCTIONS), "Cache-mount function set differs")

for name, (offset, size, symbol) in EXPECTED_FUNCTIONS.items():
    entry = config["functions"][name]
    signature = bytes.fromhex(entry["bytes"])
    emitted_size = min(size, 256)
    check(entry["offset"] == offset, f"{name} offset differs")
    check(entry["size"] == size, f"{name} full function size differs")
    check(len(signature) == emitted_size, f"{name} emitted prefix length differs")
    check(4 <= len(signature) <= 256 and len(signature) % 4 == 0,
          f"{name} signature violates the engine's 4..256-byte instruction limit")
    check(entry["symbol"] == symbol, f"{name} symbol differs")
    check(offset % 4 == 0 and offset + size <= len(text), f"{name} full function range is outside text")
    check(text[offset:offset + emitted_size] == signature, f"{name} emitted bytes differ from dump")
    check(text.count(signature) == 1, f"{name} signature is not unique")
    print(f"{name:24s} 0x{offset:06X}  full {size:3d} / emitted {len(signature):3d} bytes  OK")

check(text[0xA4CB8:0xA4CC0] == b"\0" * 8, "Unmount function boundary differs")
check(text[0xDF7EC:0xDF7F0] == b"\0" * 4, "MountCache function boundary differs")
unmount_xrefs = adrp_add_xrefs(0x8C902D)
mount_cache_xrefs = adrp_add_xrefs(0x8D6589)
check(set(unmount_xrefs) == {0xA4C00, 0xA4C84}, "Unmount assertion xrefs differ")
check(set(mount_cache_xrefs) == {0xDF5D0, 0xDF654, 0xDF714, 0xDF79C, 0xDF834, 0xDF8D4},
      "MountCacheStorage assertion xrefs differ")
check(struct.unpack_from("<Q", data_r, 0xB272A8 - 0xAE9000)[0] == TEXT_BASE + 0xA4214,
      "GetAttribute vtable pointer differs")

for name, (offset, expected_hex) in SVC_WRAPPERS.items():
    expected = bytes.fromhex(expected_hex)
    actual = text[offset:offset + len(expected)]
    check(actual == expected, f"{name} bytes differ at 0x{offset:X}")
    print(f"{name:24s} 0x{offset:06X}  {len(expected):3d} bytes  OK")

scan_offset = 0x168B00
scan = text[scan_offset:scan_offset + 0x120]
for name in ("event-signal", "event-clear"):
    offset, expected_hex = SVC_WRAPPERS[name]
    expected = bytes.fromhex(expected_hex)
    check(scan.count(expected) == 1, f"{name} is not unique in event scan")
    check(scan_offset + scan.index(expected) == offset, f"{name} event-scan offset differs")
print(f"{'eventSyscallScan':24s} 0x{scan_offset:06X}  0x120 bytes  OK")

capture_offset = 0x168000
check(capture_offset <= 0x168AD8 and capture_offset + 4096 >= 0x168E34,
      "Syscall capture does not cover the SVC wrapper table")
print(f"{'syscallCapture':24s} 0x{capture_offset:06X}  4096 bytes  OK")
print(f"PASS: {checks} static checks; all emitted and documented host-SDK bytes match the text dump")
