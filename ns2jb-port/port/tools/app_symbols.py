#!/usr/bin/env python3
import argparse
from core_derive import DATA_R_PATH, RODATA_PATH, dynamic_table, symbols


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pattern", nargs="?", default="", help="case-insensitive substring")
    parser.add_argument("--defined-only", action="store_true")
    args = parser.parse_args()
    dynamic = dynamic_table(DATA_R_PATH.read_bytes())
    symbol_list = symbols(RODATA_PATH.read_bytes(), dynamic)
    print(f"dynamic symbols: {len(symbol_list)}")
    pattern = args.pattern.lower()
    for index, (name, info, shndx, value, size) in enumerate(symbol_list):
        if pattern not in name.lower() or (args.defined_only and shndx == 0):
            continue
        print(f"{index:5d} shndx={shndx:5d} info=0x{info:02x} value=0x{value:x} size=0x{size:x} {name}")


if __name__ == "__main__":
    main()
