(async function () {
  // Raw-svc thread lifecycle stress: repeated create/start/exit/wait/close
  // cycles of one immediate-exit thread. Isolates whether the game death seen
  // at the acquisition's second wave is raw-thread lifecycle instability.
  const QUERY_OFFSET = 0x168B0Cn;
  const EXPECTED_QUERY = 'e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6';
  const LONGJMP_OFFSET = 0x5511B4n;
  const LONGJMP_BYTES = '135040a9155841a9176042a9196843a91b7044a91d7845a9023440f95f0000910824476d0a2c486d0c34496d0e3c4a6d3f00007120149f1ac0031fd6';
  const SVC_EXIT_THREAD = 0x168B4Cn;
  const EXIT_THREAD_BYTES = '410100d4c0035fd6';
  const SVC_CREATE_THREAD = 0x168B2Cn;
  const CREATE_THREAD_BYTES = 'e00f1ff8010100d4e20340f9410000b9ff430091c0035fd6';
  const SVC_START_THREAD = 0x168B44n;
  const START_THREAD_BYTES = '210100d4c0035fd6';
  const SVC_CLOSE_HANDLE = 0x168BE4n;
  const CLOSE_HANDLE_BYTES = 'c10200d4c0035fd6';
  const SVC_WAIT_SYNC = 0x168BF4n;
  const WAIT_SYNC_BYTES = 'e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6';
  const SVC_GET_PRIORITY = 0x168B5Cn;
  const GET_PRIORITY_BYTES = 'e00f1ff8810100d4e20340f9410000b9ff430091c0035fd6';
  const MANAGER_PTR_OFFSET = 0xB22280n;
  const MANAGER_BIAS = 0xF0n, LIST_SENTINEL = 0x1D0n, NODE_HANDLE = 0x1B0n;
  const CYCLES = 30;
  const STACK_BYTES = 0x14000n;
  const WAIT_NS = 0x77359400n;
  const hex = value => '0x' + BigInt(value).toString(16);
  const require = (condition, message) => { if (!condition) throw Error(message); };
  const fromHex = text => Uint8Array.from(text.match(/.{2}/g), byte => parseInt(byte, 16));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  const align = raw => {
    require((raw & 0xFFFn) === 0n, 'malloc is not page aligned: ' + hex(raw));
    return raw;
  };
  let aux = 0n, ctrl = 0n, frame = 0n, stack = 0n, qm = 0n, sdk = 0n;
  const verdict = {probe: 'raw-svc-cycle', cycles: 0, error: null};

  function query(address) {
    if (address < 0n || address >= 1n << 39n) return null;
    const result = call_rop(qm, aux, aux + 0x40n, address);
    if (result !== 0n) return null;
    return {base: read64(aux), size: read64(aux + 8n), permissions: Number(read32(aux + 0x18n))};
  }

  function expectCode(offset, bytes, label) {
    require(equal(read_buffer(sdk + offset, bytes.length / 2), fromHex(bytes)), label + ' bytes differ');
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
    const sdkRegion = query(qm);
    require(sdkRegion && sdkRegion.base + QUERY_OFFSET === qm && sdkRegion.size >= 0x602000n &&
      sdkRegion.permissions === 5, 'Unexpected SDK text region');
    sdk = sdkRegion.base;
    require(equal(read_buffer(qm, 32), fromHex(EXPECTED_QUERY)), 'svcQueryMemory bytes differ');
    expectCode(LONGJMP_OFFSET, LONGJMP_BYTES, 'longjmp');
    expectCode(SVC_EXIT_THREAD, EXIT_THREAD_BYTES, 'ExitThread');
    expectCode(SVC_CREATE_THREAD, CREATE_THREAD_BYTES, 'CreateThread wrapper');
    expectCode(SVC_START_THREAD, START_THREAD_BYTES, 'StartThread');
    expectCode(SVC_CLOSE_HANDLE, CLOSE_HANDLE_BYTES, 'CloseHandle');
    expectCode(SVC_WAIT_SYNC, WAIT_SYNC_BYTES, 'WaitSynchronization wrapper');
    expectCode(SVC_GET_PRIORITY, GET_PRIORITY_BYTES, 'GetThreadPriority wrapper');

    ctrl = align(malloc(0x2000));
    frame = align(malloc(0x2000));
    stack = align(malloc(STACK_BYTES + 0x1000n));
    require(ctrl && frame && stack, 'probe allocation failed');
    write64(frame + 0x58n, sdk + SVC_EXIT_THREAD);
    write64(frame + 0x68n, stack + STACK_BYTES);

    const manager = read64(sdk + MANAGER_PTR_OFFSET) + MANAGER_BIAS;
    const sentinel = manager + LIST_SENTINEL;
    const node = read64(sentinel);
    require(node !== sentinel && node % 8n === 0n, 'Thread manager list is empty or corrupt');
    const threadHandle = Number(read32(node + NODE_HANDLE));
    require(threadHandle > 0 && threadHandle < 0xffff8000, 'Invalid borrowed thread handle');
    const priorityResult = call_rop(sdk + SVC_GET_PRIORITY, ctrl + 0x20n, BigInt(threadHandle), 0n);
    require(priorityResult === 0n, 'GetThreadPriority failed: ' + hex(priorityResult));
    const priority = BigInt(Number(read32(ctrl + 0x20n)));
    require(priority > 0n && priority < 64n, 'Invalid borrowed priority: ' + priority);
    await log(JSON.stringify({step: 'borrowed', priority: Number(priority)}));

    for (let cycle = 0; cycle < CYCLES; cycle++) {
      write64(ctrl, 0n);
      const created = call_rop(sdk + SVC_CREATE_THREAD, ctrl, sdk + LONGJMP_OFFSET, frame,
        stack + STACK_BYTES, priority, 2n);
      require(created === 0n, 'cycle ' + cycle + ' create failed: ' + hex(created));
      const handle = Number(read32(ctrl));
      require(handle > 0 && handle < 0xffff8000, 'cycle ' + cycle + ' invalid handle');
      const started = call_rop(sdk + SVC_START_THREAD, BigInt(handle), 0n, 0n);
      require(started === 0n, 'cycle ' + cycle + ' start failed: ' + hex(started));
      write64(ctrl + 0x08n, 0n);
      write64(ctrl + 0x10n, BigInt(handle));
      const waited = call_rop(sdk + SVC_WAIT_SYNC, ctrl + 0x08n, ctrl + 0x10n, 1n, WAIT_NS);
      require(waited === 0n, 'cycle ' + cycle + ' wait failed: ' + hex(waited));
      const closed = call_rop(sdk + SVC_CLOSE_HANDLE, BigInt(handle), 0n, 0n);
      require(closed === 0n, 'cycle ' + cycle + ' close failed: ' + hex(closed));
      verdict.cycles = cycle + 1;
      if (cycle % 5 === 4) await log(JSON.stringify({step: 'cycle', count: cycle + 1}));
    }
  } catch (error) {
    verdict.error = error.message;
  } finally {
    await log(JSON.stringify(verdict));
    for (const allocation of [stack, frame, ctrl]) if (allocation !== 0n) free(allocation);
    if (aux !== 0n) free(aux);
  }
})();
