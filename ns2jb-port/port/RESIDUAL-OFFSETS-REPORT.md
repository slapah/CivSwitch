# Civ7 residual offsets and signatures

## Scope and result

This report covers the SmileBASIC-specific values left outside the core SDK, app thread/event/timing/hash/affinity, mount/sdk-proxy/RomFS, and engine-implementation workstreams. The sweep covered every CJS/JSON file under `ns2jb-main/engine`, including literal offsets, instruction signatures, title IDs, and capture-size checks. The handoff, bridge contract, app-layer report, FS requirements, and core-offsets report were also read.

No network or hardware calls were made. Civ7 values below are relative to the SDK module text base, not the CivSwitch `sdk_base` anchor. Every emitted host-SDK signature was compared directly with `dump/4e102a4000.bin`; no offset was inferred from a byte-pattern hit alone.

Files produced by this workstream:

- `port/civ7-app/cache-mount-sdk.json`: complete Civ7 replacement for the reference cache-mount signature file.
- `port/tools/residual_validate.py`: standard-library validator for the emitted config and the residual syscall values documented here.
- This report.

`port/civ7-app/ro-sm-code.json` was deliberately **not** created. The SM candidate is an FS-process global, not a Civ7 SDK function, so a host replacement signature config would describe the wrong module.

## 1. Cache-mount SDK signatures

The reference `memory/cache-mount.cjs` verifies `Unmount` and `MountCache`, then calls them as `sdk + offset` with a mount name in `x0` and a cache index in `w1`. `GetAttribute` is not called by that file but belongs to the same reference JSON and was replaced for completeness. This helper has no caller in the pipeline; emitting its config does not enable cache mounting or alter the acquisition path.

| Function | Civ7 offset | Full function size | Emitted verification bytes | Static identification |
|---|---:|---:|---:|---|
| `detail::Unmount(const char *)` | `0x0A4B70` | 328 (`0x148`) | First 256 bytes | Mount-table unmount and successful-unmount hook flow; two `Unmount` assertion references at `0xA4C00` and `0xA4C84`; complete function ends before padding at `0xA4CB8`. The following function is `IsMounted`, not another unmount candidate. |
| `MountCacheStorage(const char *, int)` | `0x0DF6B0` | 316 (`0x13C`) | First 256 bytes | Cache-mount wrapper between the no-index and application-ID overloads; preserves argument `w1` and forwards it as `w7`; two `MountCacheStorage` assertion references inside the function; complete function ends at `0xDF7EC`. |
| `FileSystemAccessor::GetSaveDataAttribute` | `0x0A4214` | 32 (`0x20`) | Full 32 bytes | Exact 32-byte match to the reference implementation and unique in Civ7 text; the data-R pointer at module `0xB272A8` is `dump_base + 0xA4214`. |

The JSON `size` fields retain the full semantic function extents. The `bytes` fields are verification prefixes, capped at 256 bytes for `Unmount` and `MountCache`, because `NativeClient.verifyFunction` accepts only 4..256 instruction bytes in multiples of four. Function identity and extents are separately supported by the full-range boundary and assertion-xref evidence above; the truncated tail bytes are not emitted as verification signatures.

The JSON's `sha256` is the SHA-256 of the complete `0x602000`-byte text dump, `afaa7c04bffe9f269f5e87b7188da789ab5e59bc87a74acce10c1874432452c3`. Its `base` records the dumped session base `0x4e102a4000` for pointer evidence only; it is ASLR-dependent and must not be used as a fixed live base.

Integration: if `cache-mount.cjs` is ever enabled, materialize this file as its `cache-mount-sdk.json`. There is no current pipeline integration need because that helper is unused. Do not substitute these functions for the mount-table/RomFS artifacts owned by the mount workstream.

## 2. Additional host-SDK syscall residuals

These literals occur outside the original app/core JSON inventory.

### `ro/worker-control.cjs`: CancelSynchronization

`cancelCode` is verified and called with an API-worker handle to cancel synchronization before binding or cancelling the retained workers.

- Target alias: `svcCancelSynchronization`
- Civ7 offset: `0x168C0C`
- Bytes: `210300d4c0035fd6` (`svc #0x19; ret`)

### `ro/control.cjs`: event and process/thread wrappers

| Consumer / target alias | Civ7 offset | Exact dump bytes |
|---|---:|---|
| `event-signal` | `0x168BAC` | `210200d4c0035fd6` |
| `event-clear` | `0x168BB4` | `410200d4c0035fd6` |
| `thread-id` / `svcGetThreadId` | `0x168C74` | `e00f1ff8a10400d4e20340f9410000f9ff430091c0035fd6` |
| `wait-zero` / `svcWaitForAddress` | `0x168BF4` | `e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6` |
| `process-info` / `svcGetInfo` | `0x168CA4` | `e00f1ff8210500d4e20340f9410000f9ff430091c0035fd6` |

For the existing event-wrapper scanning implementation, set `nativeFunctions.eventSyscallScan` to `0x168B00`. The original `0x120`-byte window then contains exactly one signal wrapper at `0x168BAC` and one clear wrapper at `0x168BB4`. The thread-ID, wait-zero, and process-info signatures include their stack prologues; their offsets are four bytes before the SVC where applicable.

### `memory/fs-root-control.cjs`: diagnostic syscall capture

`root-capture-syscalls` only saves 4096 bytes and their hash; no later engine consumer requires a particular instruction layout. Set `nativeFunctions.syscallCapture` to `0x168000`. That page-aligned 4 KiB range covers the Civ7 wrapper table from `0x168AD8` through the final wrapper ending at `0x168E34`.

Integration: add the four named `svc*` entries above to `port/sdk-functions.civ7.json`, or use numeric entries in `target.civ7.json`. The current target aliases are `svcCancelSynchronization`, `svcGetThreadId`, `svcWaitForAddress`, and `svcGetInfo`. Set `eventSyscallScan = 0x168B00` and `syscallCapture = 0x168000`. These values are not duplicated into a new residual config because the core function table and target config already own their integration path.

## 3. `layout.sdk + 0x12a0` and the SM client

This value is **generic for the current firmware's FS process**, not SmileBASIC-specific and not derivable from the Civ7 SDK dump.

Evidence from the consumers:

1. `ro/layout.cjs` sets `layout.sdk` to the verified FS heap capture's SDK page (`range.address + 0x500000`) and validates its thread-ring header.
2. `pipeline.cjs` passes `layout.sdk + 0x12a0` to `ro/test-sm.cjs`.
3. `test-sm.cjs` reads 16 bytes at `address - 4`, requires an initialized handle, a zero initialization field, guard `0x101`, and a self-pointer at `address - 8`, then exports that FS-local SM handle and opens `pm:shell`.
4. The subsequent PM request uses the native RO system title ID, not the host application's ID.

Therefore set `smServiceOffset = 0x12A0` unchanged for Civ7 on firmware 23.0.1. Keep the existing live structural checks; this report does not claim hardware validation of the FS object. No `ro-sm-code.json` is warranted.

## 4. FS capture sizes and native-layout constants

These values describe FS/NCM or the exploit's own buffers. Changing the host application to Civ7 does not change them on the same firmware.

| Value(s) | Consumer | Classification |
|---|---|---|
| `retainedCaptureBytes = 0x4D8000`, `retainedCaptureOffset = 0x500000` | `retained/find-metadata.cjs`, `ro/install-retained.cjs`, `ro/layout.cjs`, `pipeline.cjs` | Generic FS heap-capture geometry for the current firmware. The capture starts at `page - 0x500000`; `layout.sdk` is at `range.address + 0x500000`. Set both target fields unchanged. |
| Initial pool capture `0x500000`; pool size `0x2000000`; alignment `0x200000`; external-link delta `0x3A00000` | `retained/find-metadata.cjs` | Generic FS allocator/pool geometry, not host SDK offsets. Runtime link checks remain authoritative. |
| Metadata page captures `0x1000` or `0x4000` | `retained/metadata-window.cjs`, `ro/layout.cjs` | Generic observed FS allocator-link variants; the engine intentionally accepts either and validates the selected page. |
| Bucket periods `0x28000` and `0x500000` | signed-cache and retained-memory planning | Generic observed FS cache layouts, selected and verified at runtime. |
| `sdk - 0xF38BE0`, domain/vtable deltas, `sdk + 0x830`, `sdk + 0x668`, manager `+0xD48`, waiter `+0x410` stride `0x110`, domain stride `0x30` | `ro/layout.cjs`, `ro/objects.cjs`, `ro/gate.cjs` | Generic FS-process layout for this firmware. The old vptr distance is only a candidate seed; the code infers and validates the live layout structurally. No Civ7 host replacement is needed. |
| FS `GetEventHandle` prefix `7f2303d5ff8300d1fd7b01a9fd430091` | `process/fs-execute.cjs` | Generic FS code signature. The target is obtained from the validated notifier vtable, not a host-SDK offset, and original bytes are checked before patching. |
| NCM inventory capture `1024 * 16` bytes | `firmware-dump.cjs`, `ro/ncm.cjs` | Generic protocol capacity: 2048 entries × 8 bytes. It is not a firmware-size assumption. |
| Code-file maximum 256 MiB, 64 KiB capture chunks, 1 MiB donor-file limit | `ro/files.cjs`, `firmware-dump.cjs` | Generic safety/buffer limits, not target offsets. Actual file sizes come from CodeFS `GetSize`. |

The FS values are classified generic, not unresolved. They remain subject to the engine's existing current-boot structural and hash checks. The supplied Civ7 text dump cannot independently validate FS-process bytes.

## 5. Process and title IDs

| ID | Use | Civ7 status |
|---|---|---|
| `0100c9100b06a000`, `0100b4b00f9f6000` | SmileBASIC full/demo host allow-list in `process/qualify.cjs` | Must not be accepted for Civ7. The Civ7 host program ID is **unresolved** from the supplied SDK dump. Populate `programIds.host` only from the game's NPDM or a trusted runtime identity query. |
| `0400000000000000` | Native FS identity checks in process qualification/execution | Generic system title ID; retain. |
| `0400000000000037` | Native RO donor, SM/PM identity checks, launch target, payload manifest | Generic system title ID; retain and configure `programIds.ro = "0x0400000000000037"`. |
| `0400000000000037`, `...0019`, `...000a`, `...004f`, `...0014`, `...0013`, `...001d` | Native research-target allow-list in `ro/launch.cjs` | Generic system IDs, not host IDs. They may populate `allowedRo`; only `...0037` is qualified by the existing payload manifest/policy path. Do not select an alternate without requalifying its policy and launch behavior. |

Only `programIds.host` remains unresolved among the title-ID fields. A guessed Civ7 title ID would defeat the safety check in process qualification.

## 6. Integration checklist and exclusions

For the engine/configuration workstream:

1. Add the four syscall aliases and exact bytes from section 2 to the core SDK function table, then set `eventSyscallScan` and `syscallCapture`.
2. Set `retainedCaptureBytes = 0x4D8000`, `retainedCaptureOffset = 0x500000`, and `smServiceOffset = 0x12A0`.
3. Set the native RO ID and allow-list as in section 5. Leave `programIds.host` unresolved until authoritative Civ7 identity evidence is available.
4. Use `port/civ7-app/cache-mount-sdk.json` only if the optional cache-mount helper is activated. Do not create or reference `ro-sm-code.json`.
5. Keep the core memcpy/memmove/queryMemory, app JSON, mount-table/sdk-proxy/RomFS, and engine implementation changes in their owning workstreams. The sweep found no additional unowned signature JSON or host-SDK literal offsets beyond those documented above.

## 7. Validation

Run:

```bash
python port/tools/residual_validate.py
python port/validate_offsets.py port/civ7-app/cache-mount-sdk.json
```

The residual validator passed **44 static checks**. It verified:

- text length and SHA-256;
- all three cache-mount offsets, full function sizes, emitted prefix lengths, symbols, exact prefix bytes, uniqueness, and full function boundaries;
- compliance with the engine's 4..256-byte, four-byte-aligned verification-signature limit;
- unmount and cache-mount assertion xrefs and the GetAttribute data pointer;
- all six residual SVC wrapper offsets and complete byte sequences;
- uniqueness and locations in the event scan window; and
- coverage of the diagnostic syscall capture range.

The general offset validator independently reported `3 signatures matched; 0 unresolved` against the `0x602000`-byte text dump.

Representative residual-validator output ends with:

```text
syscallCapture           0x168000  4096 bytes  OK
PASS: 44 static checks; all emitted and documented host-SDK bytes match the text dump
```

Static validation does not exercise relocated calls, mounting, IPC, the FS SM object, capture geometry, or process identity on hardware. Those remain runtime bring-up checks, with the unresolved host program ID explicitly blocking full process qualification until supplied.
