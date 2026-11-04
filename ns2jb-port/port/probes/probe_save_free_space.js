(async function () {
  const QUERY_OFFSET = 0x168B0Cn;
  const GET_FREE_SPACE_OFFSET = 0xA75D0n;
  const REQUIRED_FREE = 0x1410000n;
  const EXPECTED_QUERY = 'e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6';
  const EXPECTED_FREE_SPACE = 'ff4301d1fd7b01a9f71300f9f65703a9f44f04a9fd43009157c08b52f705a072ff0700f9f40301aaf30300aaf503172a90011594c001003666fd1494f60300aa';
  const hex = value => '0x' + BigInt(value).toString(16);
  const require = (condition, message) => { if (!condition) throw Error(message); };
  const fromHex = text => Uint8Array.from(text.match(/.{2}/g), byte => parseInt(byte, 16));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  let aux = 0n, qm = 0n;

  function query(address) {
    if (address < 0n || address >= 1n << 39n) return null;
    const result = call_rop(qm, aux, aux + 0x40n, address);
    if (result !== 0n) return null;
    return {base: read64(aux), size: read64(aux + 8n), permissions: Number(read32(aux + 0x18n))};
  }

  function checked(address, length, write = false) {
    require(address >= 0n && address < 1n << 39n, 'Invalid address');
    const region = query(address);
    require(region && region.base <= address && address + BigInt(length) <= region.base + region.size,
      'Unmapped range at ' + hex(address));
    require((region.permissions & (write ? 2 : 1)) !== 0, 'Permission denied');
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
    checked(qm, 32);
    const sdkRegion = query(qm);
    require(sdkRegion.base + QUERY_OFFSET === qm && sdkRegion.size >= 0x602000n,
      'Unexpected SDK text region');
    const sdk = sdkRegion.base;
    require(equal(read_buffer(qm, 32), fromHex(EXPECTED_QUERY)), 'svcQueryMemory bytes differ');
    const getFreeSpace = sdk + GET_FREE_SPACE_OFFSET;
    checked(getFreeSpace, EXPECTED_FREE_SPACE.length / 2);
    require(equal(read_buffer(getFreeSpace, EXPECTED_FREE_SPACE.length / 2), fromHex(EXPECTED_FREE_SPACE)),
      'GetFreeSpaceSize bytes differ');

    const output = aux + 0x80n, path = aux + 0xC0n;
    checked(output, 8, true);
    checked(path, 7, true);
    write64(output, 0n);
    write_string(path, 'save:/');
    const result = call_rop(getFreeSpace, output, path);
    const free = read64(output);
    await log(JSON.stringify({path: 'save:/', result: hex(result), freeBytes: hex(free),
      requiredExclusive: hex(REQUIRED_FREE), passes: result === 0n && free > REQUIRED_FREE}));
  } catch (error) {
    await log('probe_save_free_space FATAL: ' + error.message);
  } finally {
    if (aux !== 0n) free(aux);
  }
})();
