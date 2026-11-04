# Read-only Civ7 runtime probes

These payloads run inside the CivSwitch closure as independent one-shot evaluations, not exploit stages. They were run with operator approval and completed without save-FS mutation or FS acquisition. The one exception is `probe_raw_svc_thread.js`, which creates kernel threads; its boundary is documented in its own section.

## `probe_mount_list.js`

- Resolves the true SDK text base with the established bounded `svcQueryMemory` wrapper scan and verifies the wrapper at module `+0x168B0C`.
- Byte-checks all four entries in `port/sdk-layout.civ7.json`.
- Queries memory before every list-derived read, including the writable mount head at SDK `+0xB35870`.
- Walks at most 32 nodes, rejecting loops, bad links, unmapped/partial objects, and non-ASCII names.
- Logs every mount and captures manager/object IDs for `save` and `rom`. It does not close mounts, clone sessions, invoke FS commands, or assume SmileBASIC's session-manager layout.
- Captures RomFS vtables, the storage/service chain, raw manager state, and borrowed handles with guarded reads. Optional reads report null rather than dereferencing an invalid pointer.
- Success includes `save`/`rom` booleans for R10/R12. Missing mounts are reported, not synthesized. Hardware found `save`, `rom`, and `cache`, with the layout values recorded in `MOUNT-OFFSETS-REPORT.md`.

## `probe_save_free_space.js`

- Verifies the public wrapper at SDK `+0xA75D0` and calls `GetFreeSpaceSize` on the literal path `save:/`.
- Uses only two small owned output/path buffers. The only writes are to those owned buffers; there are no save-FS writes, mount operations, IPC session creation, or handle acquisition.
- Logs the native result, free bytes, and whether free space is strictly greater than `0x1410000` (R11). A native error is a failed/inconclusive check, not zero free space.

## `probe_allocation_36m.js`

- Attempts exactly `malloc(0x2400000)` and requires page alignment.
- Uses `svcQueryMemory` at the first and last pages to require one fully covering type-5, permission-3 region with zero attributes, IPC references, and device references.
- Logs feasibility and releases the allocation in `finally`, including failure paths. This is a one-shot R2 check only; it does not test hours-long retention or heap quiescence.

## `probe_call6_memcpy.js`

- Calls canonical `memcpy` with six native arguments and verifies a 64-byte read-back.
- Uses only owned source, destination, and query buffers and frees all of them.
- Passed on hardware, confirming that the continuation-record/six-argument transport works. It does not create threads or touch the save FS.

## `probe_raw_svc_thread.js`

- Hardware-pending; not yet run on console.
- Tests the raw `svcCreateThread` hypothesis from `APP-OFFSETS-REPORT.md`: the direct `nn::os::CreateThread` hang is either the manager lock/list registration or the kernel SVC itself, and only runtime evidence can distinguish them. This probe bypasses nn::os entirely, calling the bare syscall wrappers found in the nnSdk dump: `svcCreateThread` wrapper at SDK `+0x168B2C`, `svcStartThread` `+0x168B44`, `svcExitThread` `+0x168B4C` (svc #0x0A — **not** `+0x168B24`, which is svcExitProcess and would kill the game), `svcCloseHandle` `+0x168BE4`, and the `svcWaitSynchronization` wrapper `+0x168BF4`.
- Phase A creates one thread whose jmp_buf jumps directly to `svcExitThread`, then waits on its handle. A clean wait proves raw kernel thread creation works; a nonzero create result or a hang after the `create-attempt` log line proves the block is kernel-side.
- Phase B, only if A passed, runs one full worker-frame chain (`longjmp` -> `loadTable` -> `call4` -> `memmove` -> `saveResult64` -> `svcExitThread`) using the same one-call layout `shared/frames.cjs` builds, and verifies the sentinel write, the stored result, and clean thread exit.
- Boundary: at most one kernel thread exists at a time; every handle is closed and every allocation freed in `finally`. No nn::os thread functions, services, sessions, FS commands, sockets, or save paths are used. Each phase makes exactly one create attempt and never retries. Worst case is a Civ7 process hang or crash requiring relaunch.

## Safety boundary

Before the query wrapper is available, each payload uses only the contract's established read-only scan of the executable SDK anchor range. Once found, the wrapper is queried and byte-verified. All subsequent pointer-derived memory reads are bounded and preceded by `svcQueryMemory`; malformed pointers fail before `read64`/`read_buffer` dereference. Auxiliary allocations are always freed.

No save-FS file or directory commands, writes, unmounts, domain operations, service acquisition, thread creation, sockets, or exploit-stage functions are present. `log()` uses the already-established CivSwitch evaluation channel; these payloads do not open a channel themselves.

## Validation

From the project root:

```
python port/tools/mount_verify.py
python port/tools/mount_probe_validate.py
python port/tools/raw_svc_probe_validate.py
```

The first command byte-verifies all emitted static offsets. The second checks probe constants against those verified values and audits the payloads' allocation cleanup and forbidden-operation boundary. The third byte-verifies every raw-svc gadget and frame-chain constant in `probe_raw_svc_thread.js` against `dump/4e102a4000.bin` and audits its cleanup and safety boundary. All payloads also pass Node 24.21.0 syntax checks via the machine's bundled VSCodium Node runtime. Hardware execution remains required for the actual R2/R10/R11/R12 and raw-svc thread results.
