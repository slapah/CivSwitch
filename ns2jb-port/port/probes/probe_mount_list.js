(async function () {
  const QUERY_OFFSET = 0x168B0Cn;
  const MOUNT_TABLE_OFFSET = 0xB35870n;
  const ADDRESS_LIMIT = 1n << 39n;
  const EXPECTED_QUERY = 'e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6';
  const VERIFIED = [
    [0xAAF10n, 'e20301aae10300aa405400f000c0219134f41414'],
    [0xA4420n, 'fd7bbca9f85f01a9f65702a9f44f03a9fd030091c20300b414400091f70300aaf60302aae00314aaf50301aad507159453409e52b306a072f80317aa1f2003d5180740f91f0317eb2001005400430091e10316aa02028052760a159420ffff35f3031f2a082300d1a80200f9e00314aacc071594e003132af44f43a9f65742a9f85f41a9fd7bc4a8c0035fd653c08b52f305a072e003132af44f43a9f65742a9f85f41a9fd7bc4a8c0035fd600000000'],
    [0xA4360n, 'ff0301d1fd7b01a9f65702a9f44f03a9fd43009113400091f60300aaf40301aae00313aa07081594f50316aa1f2003d5b50640f9bf0216ebe0020054a0420091e10314aa02028052aa0a159420ffff35a92240a90a0140f9280500f9a90240f9090100f9550500f9aa0200f9a88e5ff8e00315aa080540f900013fd6e00313aaf44f43a9f65742a9fd7b41a9ff030191f407151453409e52b306a072414100b0212c0f91e00313aae20314aa010e1594a01300d1b3c31fb86e08159400000000'],
    [0xD3430n, 'fd7bbda9fc0b00f9fd030091f44f02a9ff430cd1f40300aae00302aaf30301aa68521494e9031faaea3f00911f2003d50c6869380800098b4c0100344b01098b6c0100390c0540392c010034290900916c0500393f010c71c1feff540800098bea3f00914901098b05000014ea3f0091080500914901098b290500913f010039e903202a2901080b1f2003d51f2003d50a15403829050011caffff353f010c7188010054800a40f9e23f0091e10313aa080040f9083140f900013fd6ff430c91f44f42a9fc0b40f9fd7bc3a8c0035fd640c09c52c005a072ff430c91f44f42a9fc0b40f9fd7bc3a8c0035fd6'],
  ];
  const hex = value => '0x' + BigInt(value).toString(16);
  const require = (condition, message) => { if (!condition) throw Error(message); };
  const fromHex = text => Uint8Array.from(text.match(/.{2}/g), byte => parseInt(byte, 16));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let aux = 0n;
  let qm = 0n;

  function query(address) {
    if (address < 0n || address >= ADDRESS_LIMIT) return null;
    const result = call_rop(qm, aux, aux + 0x40n, address);
    if (result !== 0n) return null;
    return {
      base: read64(aux), size: read64(aux + 8n),
      type: Number(read32(aux + 0x10n)), attributes: Number(read32(aux + 0x14n)),
      permissions: Number(read32(aux + 0x18n)),
      ipcReferences: Number(read32(aux + 0x1Cn)), deviceReferences: Number(read32(aux + 0x20n)),
    };
  }

  function checkedRegion(address, length, write = false) {
    require(address >= 0n && address < ADDRESS_LIMIT && Number.isInteger(length) && length >= 0,
      'Invalid read range');
    const region = query(address);
    require(region && region.base <= address && address + BigInt(length) <= region.base + region.size,
      'Unmapped or partial read at ' + hex(address));
    require((region.permissions & (write ? 2 : 1)) !== 0, 'Permission denied at ' + hex(address));
    return region;
  }

  function safeRead(address, length) {
    checkedRegion(address, length);
    return read_buffer(address, length);
  }

  function qword(bytes, offset) { return view(bytes).getBigUint64(offset, true); }
  function word(bytes, offset) { return view(bytes).getUint32(offset, true); }

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
    const sdkRegion = checkedRegion(qm, 32);
    require(sdkRegion.base + QUERY_OFFSET === qm && sdkRegion.size >= 0x602000n,
      'Unexpected SDK text region');
    require((sdkRegion.permissions & 4) !== 0, 'SDK text is not executable');
    const sdk = sdkRegion.base;
    require(equal(safeRead(qm, 32), fromHex(EXPECTED_QUERY)), 'svcQueryMemory bytes differ');
    for (const [offset, expected] of VERIFIED) {
      require(equal(safeRead(sdk + offset, expected.length / 2), fromHex(expected)),
        'Mount verification bytes differ at ' + hex(offset));
    }

    const head = sdk + MOUNT_TABLE_OFFSET;
    checkedRegion(head, 16, true);
    let next = qword(safeRead(head + 8n, 8), 0);
    let previousLink = head;
    const seen = new Set();
    let save = false, rom = false;
    while (next !== head) {
      require(next > 0n && next < ADDRESS_LIMIT && (next & 7n) === 0n && !seen.has(hex(next)) && seen.size < 32,
        'Invalid mount list link ' + hex(next));
      seen.add(hex(next));
      const accessor = next - 8n;
      const bytes = safeRead(accessor, 48);
      require(qword(bytes, 8) === previousLink, 'Broken mount previous link');
      const implementation = qword(bytes, 40);
      const nameBytes = bytes.subarray(24, 40);
      let name = '';
      for (const byte of nameBytes) {
        if (byte === 0) break;
        require(byte >= 0x20 && byte <= 0x7E, 'Non-ASCII mount name');
        name += String.fromCharCode(byte);
      }
      require(name.length > 0, 'Empty mount name');
      const implementationBytes = safeRead(implementation, name === 'rom' ? 0x128 : 24);
      const service = qword(implementationBytes, 16);
      const moduleOffset = value => value >= sdk && value < sdk + 0xB52000n ? hex(value - sdk) : hex(value);
      const captureService = serviceBytes => {
        const manager = qword(serviceBytes, 16);
        const state = safeRead(manager, 0x80);
        const slots = qword(state, 16);
        const stateWords = [];
        for (let offset = 0; offset < 0x80; offset += 4) {
          const value = word(state, offset);
          if (value) stateWords.push([offset, value]);
        }
        let borrowed = null;
        if (slots > 0n && slots < ADDRESS_LIMIT) {
          const region = query(slots);
          if (region && region.base <= slots && slots + 4n <= region.base + region.size && (region.permissions & 1) !== 0)
            borrowed = '0x' + word(safeRead(slots, 4), 0).toString(16);
        }
        return {
          serviceVtable: moduleOffset(qword(serviceBytes, 0)), manager: hex(manager),
          objectId: '0x' + word(serviceBytes, 24).toString(16), managerStateSize: word(state, 8),
          managerStateWords: stateWords, managerStateHex: Array.from(state).map(byte => byte.toString(16).padStart(2, '0')).join(''),
          slots: hex(slots), borrowed,
        };
      };
      const entry = {name, accessor: hex(accessor), implementation: hex(implementation), service: hex(service)};
      if (name === 'save' || name === 'rom') {
        Object.assign(entry, captureService(safeRead(service, 32)));
        if (name === 'rom') {
          const storage = qword(implementationBytes, 0x118);
          require(storage === qword(implementationBytes, 0x120), 'RomFS storage pointers differ');
          const wrapper = safeRead(storage, 16);
          const storageServiceAddress = qword(wrapper, 8);
          entry.implementationVtable = moduleOffset(qword(implementationBytes, 0));
          entry.storage = hex(storage);
          entry.storageWrapperVtable = moduleOffset(qword(wrapper, 0));
          entry.storageServiceAddress = hex(storageServiceAddress);
          entry.storageService = captureService(safeRead(storageServiceAddress, 32));
        }
        if (name === 'save') save = true;
        if (name === 'rom') rom = true;
      }
      await log(JSON.stringify(entry));
      previousLink = next;
      next = qword(bytes, 16);
    }
    require(previousLink === qword(safeRead(head, 8), 0), 'Broken mount head back link');
    await log(JSON.stringify({mounts: seen.size, save, rom, mountTable: hex(head), status: 'ok'}));
  } catch (error) {
    await log('probe_mount_list FATAL: ' + error.message);
  } finally {
    if (aux !== 0n) free(aux);
  }
})();
