#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def signatures(value, path="$"):
    if isinstance(value, dict):
        if "offset" in value and "bytes" in value:
            yield path, value
        elif "functionOffset" in value and "bytes" in value:
            yield path, {**value, "offset": value["functionOffset"]}
        for key, child in value.items():
            yield from signatures(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from signatures(child, f"{path}[{index}]")


def validate(file, text):
    data = json.loads(file.read_text())
    checked = 0
    unresolved = 0
    errors = []
    for location, entry in signatures(data):
        offset = entry["offset"]
        expected = entry["bytes"]
        if not isinstance(offset, int) or isinstance(offset, bool):
            unresolved += 1
            continue
        if not isinstance(expected, str) or len(expected) % 2:
            errors.append(f"{location}: bytes must be an even-length hex string")
            continue
        try:
            expected_bytes = bytes.fromhex(expected)
        except ValueError:
            errors.append(f"{location}: bytes must be hexadecimal")
            continue
        if not expected_bytes or len(expected_bytes) > 256 or len(expected_bytes) % 4:
            errors.append(f"{location}: instruction bytes must contain 4..256 bytes in multiples of 4")
            continue
        if offset < 0 or offset + len(expected_bytes) > len(text):
            errors.append(f"{location}: offset {offset:#x} and length {len(expected_bytes):#x} exceed the text dump")
            continue
        actual = text[offset:offset + len(expected_bytes)]
        if actual != expected_bytes:
            errors.append(f"{location}: bytes differ at {offset:#x}; expected {expected_bytes.hex()}, dump has {actual.hex()}")
            continue
        checked += 1
    return checked, unresolved, errors


def main():
    parser = argparse.ArgumentParser(description="Validate JSON function signatures against the Civ7 SDK text dump")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--text", type=Path, default=Path(__file__).resolve().parent.parent / "dump" / "4e102a4000.bin")
    parser.add_argument("--require-complete", action="store_true", help="fail when a signature has a noninteger/unresolved offset")
    args = parser.parse_args()
    text = args.text.read_bytes()
    failed = False
    total = 0
    for file in args.files:
        try:
            checked, unresolved, errors = validate(file, text)
        except (OSError, ValueError) as error:
            print(f"FAIL {file}: {error}")
            failed = True
            continue
        total += checked
        status = "FAIL" if errors or (args.require_complete and unresolved) else "OK"
        print(f"{status} {file}: {checked} signatures matched; {unresolved} unresolved")
        for error in errors:
            print(f"  {error}")
        failed |= bool(errors) or (args.require_complete and bool(unresolved))
    print(f"Validated {total} function signatures against {args.text} ({len(text):#x} bytes)")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
