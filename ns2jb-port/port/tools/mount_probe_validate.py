#!/usr/bin/env python3
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    probes = root / "port/probes"
    mount = (probes / "probe_mount_list.js").read_text()
    save = (probes / "probe_save_free_space.js").read_text()
    allocation = (probes / "probe_allocation_36m.js").read_text()
    call6 = (probes / "probe_call6_memcpy.js").read_text()
    layout = json.loads((root / "port/sdk-layout.civ7.json").read_text())
    proxy = json.loads((root / "port/civ7-app/sdk-proxy-code.json").read_text())
    query_bytes = "e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6"
    free_space_bytes = "ff4301d1fd7b01a9f71300f9f65703a9f44f04a9fd43009157c08b52f705a072ff0700f9f40301aaf30300aaf503172a90011594c001003666fd1494f60300aa"

    assert "const MOUNT_TABLE_OFFSET = 0xB35870n;" in mount
    assert f'"mountTableOffset": {layout["mountTableOffset"]}' in (root / "port/sdk-layout.civ7.json").read_text()
    for entry in layout["verifiedFunctions"]:
        assert f"0x{entry['offset']:X}n" in mount, f"missing mount probe offset {entry['offset']:#x}"
        assert entry["bytes"] in mount, f"missing mount probe signature {entry['offset']:#x}"
    assert "const GET_FREE_SPACE_OFFSET = 0xA75D0n;" in save
    assert free_space_bytes in save
    assert "const REQUIRED_FREE = 0x1410000n;" in save
    assert "write_string(path, 'save:/');" in save
    assert "free > REQUIRED_FREE" in save
    assert "const ALLOCATION_BYTES = 0x2400000;" in allocation
    assert "first.type === 5 && first.permissions === 3 && first.attributes === 0" in allocation
    assert "last.base === first.base && last.size === first.size" in allocation
    for text in (mount, save, allocation):
        assert f"const QUERY_OFFSET = 0x168B0Cn;" in text
        assert query_bytes in text
        assert "finally" in text
        for forbidden in ("socket(", "connect(", "write32(", "write16(", "write8(",
                          "Unmount", "CopyObject", "OpenFile", "CreateFile", "CreateDirectory",
                          "DeleteFile", "Commit", "pthread_create", "probe-reserved-gap"):
            assert forbidden not in text, f"forbidden probe operation {forbidden}"
    assert "write64(" not in mount
    assert "write_string(" not in mount
    assert "write_buffer(" not in mount
    assert "free(aux);" in mount and "free(aux);" in save
    assert "free(allocation);" in allocation and "free(aux);" in allocation
    assert "JSON.stringify(first)" not in allocation
    assert "sdk + 0x5224E0n" in call6
    assert "free(source);" in call6 and "free(destination);" in call6 and "free(aux);" in call6
    assert "CreateThread" not in call6 and "pthread_create" not in call6
    assert proxy["globalOffset"] == 0xB4B450

    for path in sorted(probes.glob("*.js")):
        text = path.read_text()
        for opening, closing in (("{", "}"), ("(", ")"), ("[", "]")):
            assert text.count(opening) == text.count(closing), f"unbalanced {opening}{closing} in {path.name}"
        print(f"OK {path.name}: constants, cleanup, and read-only safety boundary")
    print("All probe static validations passed; JavaScript/hardware execution was not performed.")


if __name__ == "__main__":
    main()
