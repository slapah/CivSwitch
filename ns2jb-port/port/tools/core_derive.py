#!/usr/bin/env python3
import argparse
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT_PATH = ROOT / "dump" / "4e102a4000.bin"
RODATA_PATH = ROOT / "dump" / "4e108a6000.bin"
DATA_R_PATH = ROOT / "dump" / "4e10d8d000.bin"
OUTPUT_PATH = ROOT / "port" / "sdk-functions.civ7.json"
RODATA_OFFSET = 0x602000
DATA_R_OFFSET = 0xAE9000
DYNAMIC_OFFSET = 0xB21980
GET_SERVICE_SYMBOL = "_ZN2nn2sm16GetServiceHandleEPNS_3svc6HandleEPKcm"
SYMBOL_NAMES = {
    "allocate": "posix_memalign",
    "getService": GET_SERVICE_SYMBOL,
    "memset": "memset",
    "memcpy": "memcpy",
    "memmove": "memmove",
}


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def dynamic_table(data_r):
    entries = {}
    for file_offset in range(DYNAMIC_OFFSET - DATA_R_OFFSET, len(data_r) - 15, 16):
        tag, value = struct.unpack_from("<QQ", data_r, file_offset)
        if tag == 0:
            return entries
        entries[tag] = value
    raise ValueError("Unterminated dynamic table")


def symbols(rodata, dynamic):
    symtab = dynamic[6]
    strtab = dynamic[5]
    result = []
    for module_offset in range(symtab, strtab, 24):
        file_offset = module_offset - RODATA_OFFSET
        name_offset, info, other, shndx, value, size = struct.unpack_from(
            "<IBBHQQ", rodata, file_offset
        )
        string_offset = strtab + name_offset - RODATA_OFFSET
        if not 0 <= string_offset < len(rodata):
            raise ValueError(f"Invalid string offset in symbol at 0x{module_offset:X}")
        end = rodata.find(b"\0", string_offset)
        if end < 0:
            raise ValueError(f"Unterminated symbol name at 0x{string_offset:X}")
        name = rodata[string_offset:end].decode("utf-8")
        result.append((name, info, shndx, value, size))
    return result


def defined_symbol(symbol_list, name):
    matches = [entry for entry in symbol_list if entry[0] == name and entry[2] != 0]
    if len(matches) != 1:
        raise ValueError(f"Expected one defined symbol {name}, found {len(matches)}")
    _, info, _, value, size = matches[0]
    if info & 0xF != 2 or value % 4 or size < 4:
        raise ValueError(f"Symbol {name} is not an aligned function")
    return value, size


def free_got_offset(rodata, dynamic, symbol_list):
    free_indices = [i for i, entry in enumerate(symbol_list) if entry[0] == "free" and entry[2] == 0]
    if len(free_indices) != 1:
        raise ValueError(f"Expected one undefined free import, found {len(free_indices)}")
    symbol_index = free_indices[0]
    rela = dynamic[23]
    rela_size = dynamic[2]
    matches = []
    for module_offset in range(rela, rela + rela_size, 24):
        file_offset = module_offset - RODATA_OFFSET
        target, info, addend = struct.unpack_from("<QQq", rodata, file_offset)
        if info >> 32 == symbol_index:
            matches.append((target, info & 0xFFFFFFFF, addend))
    if len(matches) != 1:
        raise ValueError(f"Expected one free relocation, found {len(matches)}")
    target, relocation_type, addend = matches[0]
    if relocation_type != 0x402 or addend != 0:
        raise ValueError("Unexpected free relocation form")
    return target


def adrp_page(instruction_offset, word):
    immediate = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return (instruction_offset & ~0xFFF) + (immediate << 12)


def find_plt_for_got(text, got_offset):
    matches = []
    for offset in range(0, len(text) - 16, 4):
        adrp, ldr, _, branch = struct.unpack_from("<IIII", text, offset)
        if adrp & 0x9F00001F != 0x90000010 or branch != 0xD61F0220:
            continue
        if ldr & 0xFFC003FF != 0xF9400211:
            continue
        target = adrp_page(offset, adrp) + ((ldr >> 10) & 0xFFF) * 8
        if target == got_offset:
            matches.append(offset)
    if len(matches) != 1:
        raise ValueError(f"Expected one PLT thunk for GOT 0x{got_offset:X}, found {len(matches)}")
    return matches[0]


def find_svc_wrapper(text, number):
    matches = []
    for offset in range(0, len(text) - 4, 4):
        word = struct.unpack_from("<I", text, offset)[0]
        if word & 0xFFE0001F == 0xD4000001 and (word >> 5) & 0xFFFF == number:
            matches.append(offset)
    if len(matches) != 1:
        raise ValueError(f"Expected one SVC #{number}, found {len(matches)}")
    svc_offset = matches[0]
    if number == 6:
        start = svc_offset - 4
        expected_tail = bytes.fromhex("e20340f9410000b9ff430091c0035fd6")
        if text[start:start + 4] != bytes.fromhex("e10f1ff8"):
            raise ValueError("svcQueryMemory stack prologue differs")
        if text[svc_offset + 4:svc_offset + 20] != expected_tail:
            raise ValueError("svcQueryMemory tail differs")
        return start, 24
    if text[svc_offset + 4:svc_offset + 8] != bytes.fromhex("c0035fd6"):
        raise ValueError(f"SVC #{number} is not a two-instruction wrapper")
    return svc_offset, 8


def derive(text, rodata, data_r):
    dynamic = dynamic_table(data_r)
    required_dynamic = {2, 5, 6, 10, 11, 23}
    if not required_dynamic <= dynamic.keys() or dynamic[11] != 24:
        raise ValueError("Dynamic table lacks the expected symbol/relocation layout")
    symbol_list = symbols(rodata, dynamic)
    offsets = {}
    for output_name, symbol_name in SYMBOL_NAMES.items():
        offset, size = defined_symbol(symbol_list, symbol_name)
        if size < 64:
            raise ValueError(f"Symbol {symbol_name} is too short for its signature")
        offsets[output_name] = (offset, 64)
    crc32_offset, crc32_size = defined_symbol(symbol_list, "nnutilZlib_crc32")
    if crc32_size != 8:
        raise ValueError("nnutilZlib_crc32 is no longer the expected branch wrapper")
    offsets["crc32"] = (crc32_offset, crc32_size)
    got_offset = free_got_offset(rodata, dynamic, symbol_list)
    offsets["free"] = (find_plt_for_got(text, got_offset), 16)
    offsets["send"] = find_svc_wrapper(text, 0x22)
    offsets["close"] = find_svc_wrapper(text, 0x16)
    offsets["svcQueryMemory"] = find_svc_wrapper(text, 0x06)
    offsets["svcSendSyncRequest"] = offsets["send"]
    offsets["svcCloseHandle"] = offsets["close"]
    ordered = {}
    for name in (
        "allocate", "free", "getService", "send", "close", "memset",
        "memcpy", "memmove", "svcQueryMemory", "svcSendSyncRequest", "svcCloseHandle", "crc32",
    ):
        offset, byte_count = offsets[name]
        ordered[name] = {"offset": offset, "bytes": text[offset:offset + byte_count].hex()}
    evidence = {
        "dynamic": dynamic,
        "freeGotOffset": got_offset,
        "textCrc32": zlib.crc32(text),
    }
    return ordered, evidence


def validate(functions, text):
    required = {
        "allocate", "free", "getService", "send", "close", "memset",
        "memcpy", "memmove", "svcQueryMemory", "svcSendSyncRequest", "svcCloseHandle", "crc32",
    }
    if set(functions) != required:
        raise ValueError(f"Function set differs: {set(functions) ^ required}")
    for name, entry in functions.items():
        offset = entry["offset"]
        expected = bytes.fromhex(entry["bytes"])
        if not isinstance(offset, int) or offset < 0 or offset % 4:
            raise ValueError(f"{name}: invalid offset")
        if len(expected) < 4 or len(expected) > 256 or len(expected) % 4:
            raise ValueError(f"{name}: invalid signature length")
        if offset + len(expected) > len(text):
            raise ValueError(f"{name}: signature exceeds text dump")
        if text[offset:offset + len(expected)] != expected:
            raise ValueError(f"{name}: instruction bytes differ")
    aliases = (("send", "svcSendSyncRequest"), ("close", "svcCloseHandle"))
    for canonical, alias in aliases:
        if functions[canonical] != functions[alias]:
            raise ValueError(f"Alias mismatch: {canonical}/{alias}")


def main():
    parser = argparse.ArgumentParser(description="Derive and verify Civ7 core SDK offsets")
    parser.add_argument("--write", action="store_true", help="regenerate sdk-functions.civ7.json")
    args = parser.parse_args()
    text = TEXT_PATH.read_bytes()
    rodata = RODATA_PATH.read_bytes()
    data_r = DATA_R_PATH.read_bytes()
    derived, evidence = derive(text, rodata, data_r)
    validate(derived, text)
    if args.write:
        OUTPUT_PATH.write_text(json.dumps(derived, indent=2) + "\n", encoding="utf-8")
    if OUTPUT_PATH.exists():
        emitted = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        validate(emitted, text)
        if emitted != derived:
            raise ValueError("Emitted JSON differs from freshly derived offsets/bytes")
    for name, entry in derived.items():
        print(f"{name:20s} 0x{entry['offset']:06X}  {len(entry['bytes']) // 2:2d} bytes  OK")
    print(f"text size: 0x{len(text):X}")
    print(f"text CRC-32: {evidence['textCrc32']} (0x{evidence['textCrc32']:08X})")
    print(f"free GOT: 0x{evidence['freeGotOffset']:X}")


if __name__ == "__main__":
    main()
