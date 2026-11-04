#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
from core_derive import DATA_R_PATH, RODATA_PATH, defined_symbol, dynamic_table, symbols

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "port/civ7-app"
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()
DUMP_SHA256 = hashlib.sha256(TEXT).hexdigest()
FILES = [
    "thread-code.json",
    "event-code.json",
    "timing-code.json",
    "hash-code.json",
    "thread-scheduling-reference.json",
    "compat-affinity-reference.json",
]
resolved = 0
unresolved = []


def visit(value, path):
    global resolved
    if not isinstance(value, dict):
        return
    if "offset" in value and "bytes" in value:
        if value["offset"] is None or value["bytes"] is None:
            assert value["offset"] is None and value["bytes"] is None, f"partial unresolved entry: {path}"
            unresolved.append(path)
            return
        offset = value["offset"]
        expected = bytes.fromhex(value["bytes"])
        full_size = value["size"]
        assert isinstance(full_size, int) and full_size >= 4, f"invalid full-body size: {path}"
        assert offset >= 0 and offset + full_size <= len(TEXT), f"full body exceeds dump: {path}"
        assert len(expected) >= 4 and len(expected) <= 256 and len(expected) % 4 == 0, f"invalid verification prefix length: {path}"
        assert len(expected) == min(full_size, 256), f"prefix is not the full-body maximum capped at 256: {path}"
        assert len(expected) == value["prefixSize"], f"prefixSize mismatch: {path}"
        actual = TEXT[offset:offset + len(expected)]
        assert actual == expected, f"dump mismatch: {path}"
        assert hashlib.sha256(TEXT[offset:offset + full_size]).hexdigest() == value["sha256"], f"full-body SHA-256 mismatch: {path}"
        resolved += 1
    for key, child in value.items():
        if isinstance(child, dict):
            visit(child, f"{path}.{key}")


for name in FILES:
    value = json.loads((OUT / name).read_text())
    visit(value, name)
    print(f"PASS {name}: JSON parsed and all resolved entries match dump")

thread = json.loads((OUT / "thread-code.json").read_text())
assert thread["sha256"] == DUMP_SHA256
assert thread["functions"]["exit"]["status"] == "CONFIRMED_DEFINED_SYMBOL"
assert thread["functions"]["call4"]["loadFromSelfOffset"] == 0x70
assert thread["functions"]["call4"]["size"] == 0x38
assert thread["functions"]["loadTable"]["size"] == 0x18
for name in ("call4", "loadTable", "saveResult", "saveResult64"):
    assert bytes.fromhex(thread["functions"][name]["bytes"])[-4:] == bytes.fromhex("c0035fd6"), f"bad gadget boundary: {name}"
assert TEXT[0x359b88 + 0x14:0x359b88 + 0x18] == bytes.fromhex("083940f9")
assert TEXT[0x5511b4 + 0x38:0x5511b4 + 0x3c] == bytes.fromhex("c0031fd6")
assert TEXT[0x142478:0x14247c] == bytes.fromhex("13e900f9"), "pthread_exit result store differs"
for opcode in ("7f2303d5", "5f2403d5", "df2403d5", "ff2303d5"):
    assert bytes.fromhex(opcode) not in TEXT, f"unexpected BTI/PAC opcode {opcode} in text"
print("PASS call4 variant, gadget boundaries, pthread_exit result store, and BTI/PAC opcode scan")

symbol_list = symbols(RODATA_PATH.read_bytes(), dynamic_table(DATA_R_PATH.read_bytes()))
for name, symbol, offset, size in (
    ("create", "pthread_create", 0x142180, 0x220),
    ("join", "pthread_join", 0x142480, 0xc8),
    ("exit", "pthread_exit", 0x142410, 0x70),
    ("tryWaitImplementation", "_ZN2nn2os6detail26ThreadManagerImplByHorizon20TryWaitForExitThreadEPNS0_10ThreadTypeE", 0x13e120, 0xb8),
):
    assert defined_symbol(symbol_list, symbol) == (offset, size), f"dynamic symbol mismatch: {name}"
    assert (thread["functions"][name]["offset"], thread["functions"][name]["size"]) == (offset, size)
hash_code = json.loads((OUT / "hash-code.json").read_text())
assert defined_symbol(symbol_list, "_ZN2nn6crypto18GenerateSha256HashEPvmPKvm") == (0x4d40, 0x6c)
assert (hash_code["offset"], hash_code["size"]) == (0x4d40, 0x6c)
print("PASS defined dynamic symbols for create/join/exit/try-wait/GenerateSha256Hash")
assert thread["functions"]["create"]["outputSemantics"]["status"] == "RUNTIME_DISCOVERY_REQUIRED"
assert TEXT[0x14235c:0x142360] == bytes.fromhex("e80a40b2")
assert TEXT[0x142364:0x142368] == bytes.fromhex("680200f9")
print("PASS create output-anomaly instructions and runtime-discovery gate")
direct = thread["directNnOs"]
assert direct["status"] == "NO_GO_CREATE_THREAD_HANG_UNRESOLVED"
assert direct["hardwareBlock"]["identicalPthreadCallee"].startswith("pthread_create at 0x1422d0 branches through 0x5e6b30")
assert direct["lifecycle"] == ["NO-GO: do not retry direct CreateThread or progress to StartThread until a concrete correction is identified."]
assert direct["threadType"]["requestedBytesSupported"] is False
assert direct["threadType"]["minimumBytes"] == 0x601 and direct["threadType"]["recommendedBytes"] == 0x1000
assert direct["stack"]["bytes"] == 0x14000 and direct["stack"]["separateFromThreadType"]
assert direct["cleanup"]["requiresPthreadJoin"] is False
assert direct["pthreadExit"]["compatible"] is False and direct["pthreadExit"]["resultFieldSupported"] is False
assert direct["affinity"]["compatible"] is True
assert direct["functions"]["exitContinuation"]["offset"] == 0x13e094
for name, symbol, offset, size in (
    ("create", "_ZN2nn2os12CreateThreadEPNS0_10ThreadTypeEPFvPvES3_S3_mi", 0x136d50, 0x28),
    ("start", "_ZN2nn2os11StartThreadEPNS0_10ThreadTypeE", 0x136da0, 0x14),
    ("destroy", "_ZN2nn2os13DestroyThreadEPNS0_10ThreadTypeE", 0x136d80, 0x14),
):
    assert defined_symbol(symbol_list, symbol) == (offset, size), f"direct nn::os symbol mismatch: {name}"
    assert (direct["functions"][name]["offset"], direct["functions"][name]["size"]) == (offset, size)
assert TEXT[0x137f34:0x137f38] == bytes.fromhex("7f020639"), "ThreadType+0x600 write differs"
print("PASS direct nn::os symbols, 0x1000-byte object requirement, exit continuation, cleanup and affinity gates")
recovery = thread["managerListRecovery"]
assert recovery["status"] == "STATICALLY_SUPPORTED_BOUNDED_LIST_WALK"
assert recovery["layout"] == {
    "globalManagerPointerOffset": 0xb22280,
    "managerBias": 0xf0,
    "listSentinelOffset": 0x1d0,
    "nextOffset": 0,
    "previousOffset": 8,
    "entryOffset": 0x68,
    "argumentOffset": 0x60,
    "pthreadBaseFromNode": -0x310,
    "pthreadEntryOffset": 0x1c0,
    "pthreadArgumentOffset": 0x1c8,
    "kernelHandleOffset": 0x1b0,
    "managerLockOffset": 0x1c8,
}
assert recovery["guardedWalk"]["maxNodes"] == 128
assert direct["status"] == "NO_GO_CREATE_THREAD_HANG_UNRESOLVED"
assert TEXT[0x138648:0x13864c] == bytes.fromhex("76ea00f9"), "manager sentinel initialization differs"
assert TEXT[0x13806c:0x138070] == bytes.fromhex("89ea00f9"), "manager insertion differs"
print("PASS bounded manager-list recovery layout while direct CreateThread remains NO-GO")

for file_name, function_names in (
    ("thread-code.json", ("create",)),
    ("event-code.json", ("wait", "signal")),
    ("thread-scheduling-reference.json", ("pthread_setaffinity_np",)),
):
    functions = json.loads((OUT / file_name).read_text())["functions"]
    for function_name in function_names:
        function = functions[function_name]
        assert function["size"] > 256 and function["prefixSize"] == 256 and len(bytes.fromhex(function["bytes"])) == 256
print("PASS oversized bodies retain full metadata and emit 256-byte verification prefixes")
compat = json.loads((OUT / "compat-affinity-reference.json").read_text())["pthreadAffinityCompatibility"]
data_r = (ROOT / "dump/4e10d8d000.bin").read_bytes()
captured = int.from_bytes(data_r[compat["gotOffset"] - 0xae9000:compat["gotOffset"] - 0xae9000 + 8], "little")
assert compat["target"]["capturedAddress"] == hex(captured)
print(f"PASS compat GOT captured target: {compat['target']['capturedAddress']} (not a module offset)")

expected_unresolved = {
    "timing-code.json.nativeFrequencyCode",
    "compat-affinity-reference.json.pthreadAffinityCompatibility.target",
}
assert set(unresolved) == expected_unresolved, (unresolved, expected_unresolved)
print(f"PASS total: {resolved} resolved byte signatures; {len(unresolved)} documented unresolved entries")
print(f"DUMP SHA-256: {DUMP_SHA256}")
for name in unresolved:
    print(f"UNRESOLVED {name}")
