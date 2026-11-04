(async function () {
  await log(JSON.stringify({
    Worker: typeof Worker,
    SharedArrayBuffer: typeof SharedArrayBuffer,
    Atomics: typeof Atomics,
    callRopSource: typeof call_rop === 'function' ? String(call_rop).slice(0, 160) : null,
  }));
  if (typeof Worker !== 'function') return;
  try {
    const source = `
      postMessage(JSON.stringify({
        callRop: typeof call_rop,
        read64: typeof read64,
        sdkBase: typeof sdk_base,
        malloc: typeof malloc,
      }));
    `;
    const url = URL.createObjectURL(new Blob([source], {type: 'text/javascript'}));
    const worker = new Worker(url);
    const result = await new Promise(async resolve => {
      const timer = setTimeout(() => resolve('timeout'), 3000);
      worker.onmessage = event => {
        clearTimeout(timer);
        resolve(event.data);
      };
      worker.onerror = event => {
        clearTimeout(timer);
        resolve('error: ' + event.message);
      };
    });
    worker.terminate();
    URL.revokeObjectURL(url);
    await log('worker result: ' + result);
  } catch (error) {
    await log('worker error: ' + error.message);
  }
})();
