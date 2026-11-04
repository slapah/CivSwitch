#!/usr/bin/env python3
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()


def word(offset):
    return struct.unpack_from("<I", TEXT, offset)[0]


checks = {
    0x136d54: 0x2a0503e6,
    0x136d58: 0xf9414108,
    0x136d70: 0x9103c100,
    0x138630: 0x91074276,
    0x138648: 0xf900ea76,
    0x138050: 0x91074288,
    0x13805c: 0xf900026a,
    0x138060: 0xf9000528,
    0x138068: 0xf9000513,
    0x13806c: 0xf900ea89,
    0x137f4c: 0xa905e676,
    0x137f50: 0xa906fe7a,
    0x1422f8: 0xa91c56f6,
}
for offset, expected in checks.items():
    assert word(offset) == expected, f"instruction mismatch at {offset:#x}"
print("verified manager pointer bias, sentinel, insertion, and direct/pthread entry-argument stores")
print("manager = read64(sdk + 0xb22280) + 0xf0")
print("sentinel = manager + 0x1d0; node = read64(sentinel); next = read64(node + 0)")
print("for up to 128 unique nodes: require aligned node, readable node+0x608, no cycles")
print("match read64(node+0x68) == sdk+0x5511b4 and read64(node+0x60) == ownedFrameBase")
print("pthreadBase = node-0x310; verify pthreadBase+0x1c0/+0x1c8 hold the same entry/argument")
print("revalidate node/linkage; GetCoreMask=0x1371c0, SetCoreMask=0x1371a0, TryWait=0x137110")
print("only when TryWait returns 1: DestroyThread=0x136d80; no CreateThread and no pthread_join")
print("archived example ownedFrameBase=0x597cd0f000 (ASLR-specific, never reuse blindly)")
