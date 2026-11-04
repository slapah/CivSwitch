#!/usr/bin/env python3
"""Static validation for probe_raw_svc_thread.js against the nnSdk text dump."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "port/probes/probe_raw_svc_thread.js"
DUMP = ROOT / "dump/4e102a4000.bin"
ARTIFACT = ROOT / "port/civ7-app/thread-code.json"

ARTIFACT_OFFSETS = {
    "createThread": 0x168B2C,
    "startThread": 0x168B44,
    "exitThread": 0x168B4C,
    "getThreadPriority": 0x168B5C,
    "getThreadCoreMask": 0x168B7C,
    "setThreadCoreMask": 0x168B9C,
    "getCurrentProcessorNumber": 0x168BA4,
    "closeHandle": 0x168BE4,
    "waitSynchronization": 0x168BF4,
    "readTpidrro": 0x14BA80,
}
ARTIFACT_MANAGER_LIST = {
    "globalPointerOffset": 0xB22280,
    "managerBias": 0xF0,
    "listSentinelOffset": 0x1D0,
    "nodeHandleOffset": 0x1B0,
}

EXPECTED = {
    "LONGJMP_OFFSET": ("LONGJMP_BYTES", 0x5511B4),
    "LOAD_TABLE_OFFSET": ("LOAD_TABLE_BYTES", 0x4E094),
    "CALL4_OFFSET": ("CALL4_BYTES", 0x359B88),
    "SAVE_RESULT64_OFFSET": ("SAVE_RESULT64_BYTES", 0x19BCC0),
    "MEMMOVE_OFFSET": ("MEMMOVE_BYTES", 0x522830),
    "SVC_EXIT_THREAD": ("EXIT_THREAD_BYTES", 0x168B4C),
    "SVC_CREATE_THREAD": ("CREATE_THREAD_BYTES", 0x168B2C),
    "SVC_START_THREAD": ("START_THREAD_BYTES", 0x168B44),
    "SVC_CLOSE_HANDLE": ("CLOSE_HANDLE_BYTES", 0x168BE4),
    "SVC_WAIT_SYNC": ("WAIT_SYNC_BYTES", 0x168BF4),
    "SVC_CURRENT_CORE": ("CURRENT_CORE_BYTES", 0x168BA4),
    "SVC_GET_CORE_MASK": ("GET_CORE_MASK_BYTES", 0x168B7C),
    "SVC_GET_PRIORITY": ("GET_PRIORITY_BYTES", 0x168B5C),
}


def main():
    text = PROBE.read_text()
    dump = DUMP.read_bytes()

    for offset_name, (bytes_name, offset) in EXPECTED.items():
        offset_match = re.search(rf"const {offset_name} = (?:0x([0-9A-Fa-f]+)|(\d+))n;", text)
        assert offset_match, f"missing {offset_name}"
        value = int(offset_match.group(1), 16) if offset_match.group(1) else int(offset_match.group(2))
        assert value == offset, f"{offset_name} is {value:#x}, expected {offset:#x}"
        bytes_match = re.search(rf"const {bytes_name} = '([0-9a-f]+)';", text)
        assert bytes_match, f"missing {bytes_name}"
        expected = bytes_match.group(1)
        actual = dump[offset:offset + len(expected) // 2].hex()
        assert actual == expected, f"{bytes_name} differs from dump at {offset:#x}"
        print(f"OK {bytes_name}: {len(expected) // 2} bytes verified at dump {offset:#x}")

    # The frame layout must match frames.cjs for exactly one call with no
    # dynamic arguments: tables=0x1000, stack=0x12000, size=0x17000.
    for constant in ("const RESULT = 0x800n", "TABLES = 0x1000n",
                     "FRAME_STACK = 0x12000n", "FRAME_BYTES = 0x17000n"):
        assert constant in text, f"missing frame layout constant {constant}"
    # One-call chain writes from shared/frames.cjs build().
    for write in ("write64(frameB + 0x10n, frameB + TABLES);",
                  "write64(frameB + 0x30n, ctrl + 0x20n);",
                  "write64(frameB + 0x58n, sdk + LOAD_TABLE_OFFSET);",
                  "write64(frameB + 0x68n, frameB + FRAME_STACK);",
                  "write64(frameB + TABLES, frameB + TABLES + 0x10n);",
                  "write64(frameB + TABLES + 0x80n, sdk + MEMMOVE_OFFSET);",
                  "write64(frameB + RESULT, SENTINEL);",
                  "write64(sp + 0x08n, sdk + CALL4_OFFSET);",
                  "write64(sp + 0xd8n, sdk + SAVE_RESULT64_OFFSET);",
                  "write64(sp + 0x118n, frameB + RESULT);",
                  "write64(sp + 0x128n, sdk + SVC_EXIT_THREAD);"):
        assert write in text, f"missing frame chain write: {write}"

    # Safety boundary: raw thread lifecycle only; no nn::os thread functions,
    # services, FS commands, sockets, or save paths.
    for forbidden in ("0x136D50", "0x136d50", "0x168B24", "pthread_create", "getService",
                      "OpenFile", "CreateFile", "DeleteFile", "CopyObject",
                      "socket(", "connect(", "save:/", "MountSd"):
        assert forbidden not in text, f"forbidden operation in probe: {forbidden}"
    assert "read_buffer(sdk + offset, bytes.length / 2)" in text, \
        "expectCode must read bytes.length / 2 bytes (hex string length)"
    for required in ("finally", "free(aux);", "closeHandles(sdk)",
                     "call_rop(sdk + SVC_CLOSE_HANDLE, BigInt(handle), 0n, 0n);",
                     "create-attempt"):
        assert required in text, f"missing cleanup/safety element: {required}"
    for opening, closing in (("{", "}"), ("(", ")"), ("[", "]")):
        assert text.count(opening) == text.count(closing), f"unbalanced {opening}{closing}"
    print("OK probe_raw_svc_thread.js: constants, frame layout, cleanup, and safety boundary")

    artifact = json.loads(ARTIFACT.read_text())
    raw_svc = artifact.get("rawSvc")
    assert raw_svc, "thread-code.json has no rawSvc block"
    for name, offset in ARTIFACT_OFFSETS.items():
        entry = raw_svc["functions"].get(name)
        assert entry, f"rawSvc is missing {name}"
        assert entry["offset"] == offset, \
            f"rawSvc {name} offset is {entry['offset']:#x}, expected {offset:#x}"
        actual = dump[offset:offset + len(entry["bytes"]) // 2].hex()
        assert actual == entry["bytes"], f"rawSvc {name} bytes differ from dump at {offset:#x}"
        print(f"OK rawSvc {name}: {len(entry['bytes']) // 2} bytes verified at dump {offset:#x}")
    for name, value in ARTIFACT_MANAGER_LIST.items():
        actual = raw_svc["managerList"].get(name)
        assert actual == value, f"rawSvc managerList {name} is {actual!r}, expected {value:#x}"
    print("OK rawSvc managerList: offsets match the hardware-verified layout")


if __name__ == "__main__":
    main()
