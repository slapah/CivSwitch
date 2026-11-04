(async function () {
  const QUERY_OFFSET = 0x168B0Cn;
  const ALLOCATION_BYTES = 0x2400000;
  const EXPECTED_QUERY = 'e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6';
  const hex = value => '0x' + BigInt(value).toString(16);
  const require = (condition, message) => { if (!condition) throw Error(message); };
  const fromHex = text => Uint8Array.from(text.match(/.{2}/g), byte => parseInt(byte, 16));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  let aux = 0n, allocation = 0n, qm = 0n;

  function query(address) {
    if (address < 0n || address >= 1n << 39n) return null;
    const result = call_rop(qm, aux, aux + 0x40n, address);
    if (result !== 0n) return null;
    return {
      base: read64(aux), size: read64(aux + 8n), type: Number(read32(aux + 0x10n)),
      attributes: Number(read32(aux + 0x14n)), permissions: Number(read32(aux + 0x18n)),
      ipcReferences: Number(read32(aux + 0x1Cn)), deviceReferences: Number(read32(aux + 0x20n)),
    };
  }

  function checked(address, length, write = false) {
    require(address >= 0n && address < 1n << 39n, 'Invalid address');
    const region = query(address);
    require(region && region.base <= address && address + BigInt(length) <= region.base + region.size,
      'Unmapped range at ' + hex(address));
    require((region.permissions & (write ? 2 : 1)) !== 0, 'Permission denied');
    return region;
  }

  try {
    aux = malloc(0x100);
    require(aux !== 0n, 'aux malloc failed');
    let previousHigh = 0n;
    for (let address = sdk_base; address < sdk_base + 0x5F0000n; address += 8n) {
      const pair = read64(address);
      const low = pair & 0xFFFFFFFFn, high = pair >> 32n;
      if (low === 0xF81F0FE1n && high === 0xD40000C1n) { qm = address; break; }
      if (previousHigh === 0xF81F0FE1n && low === 0xD40000C1n) { qm = address - 4n; break; }
      previousHigh = high;
    }
    require(qm !== 0n, 'svcQueryMemory wrapper not found');
    const sdkRegion = checked(qm, 32);
    require(sdkRegion.base + QUERY_OFFSET === qm && sdkRegion.size >= 0x602000n,
      'Unexpected SDK text region');
    require(equal(read_buffer(qm, 32), fromHex(EXPECTED_QUERY)), 'svcQueryMemory bytes differ');

    allocation = malloc(ALLOCATION_BYTES);
    require(allocation !== 0n, '36 MiB malloc returned null');
    require((allocation & 0xFFFn) === 0n, '36 MiB allocation is not page aligned: ' + hex(allocation));
    const first = checked(allocation, ALLOCATION_BYTES, true);
    require(first.type === 5 && first.permissions === 3 && first.attributes === 0 &&
      first.ipcReferences === 0 && first.deviceReferences === 0,
      'Allocation is not ordinary owned type-5 RW memory: base=' + hex(first.base) +
      ' size=' + hex(first.size) + ' type=' + first.type + ' permissions=' + first.permissions +
      ' attributes=' + first.attributes + ' ipcReferences=' + first.ipcReferences +
      ' deviceReferences=' + first.deviceReferences);
    const last = query(allocation + BigInt(ALLOCATION_BYTES - 4096));
    require(last && last.base === first.base && last.size === first.size,
      '36 MiB allocation crosses a memory-region boundary');
    await log(JSON.stringify({allocation: hex(allocation), bytes: hex(ALLOCATION_BYTES),
      regionBase: hex(first.base), regionSize: hex(first.size), feasible: true, freed: false}));
  } catch (error) {
    await log(JSON.stringify({allocation: hex(allocation), bytes: hex(ALLOCATION_BYTES),
      feasible: false, error: error.message}));
  } finally {
    if (allocation !== 0n) {
      free(allocation);
      await log(JSON.stringify({allocation: hex(allocation), freed: true}));
    }
    if (aux !== 0n) free(aux);
  }
})();
