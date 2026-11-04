# Workstream C — App-layer audit: SmileBASIC coupling in ns2jb

Scope: `ns2jb-main/engine/switch2/app/*`, `engine/shared/*`, `engine/lib/*`,
`run.cjs`, `engine/switch2/pipeline.cjs`. Line numbers refer to the pristine
reference tree. Severities: **blocker** (run aborts at a check or wrong code is
called), **must-adapt** (runs but wrong/unsafe on Civ7), **tunable** (works,
may need adjustment).

---

## 1. Stage-by-stage walkthrough (app layer)

Orchestration: `run.cjs:195` accepts the console TCP connection (port 39380,
`run.cjs:15`), wraps it in `NativeClient` (`lib/native.cjs:25`), runs
`lib/qualify.cjs`, starts a localhost HTTP bridge (`lib/bridge.cjs:5`) that
serializes all native calls, writes `connection.json` into the launch dir
(`run.cjs:212`), copies `engine/shared` + `engine/switch2` in
(`run.cjs:214-215`), then spawns `switch2/pipeline.cjs`. Pipeline stage 1/4
(`pipeline.cjs:34-39`) runs the four app-layer stages:

1. **`app/map.cjs`** — walks the whole 39-bit address space with
   `svcQueryMemory` (`map.cjs:7-14`), one HTTP-bridged RPC per region, and
   writes `app/memory-map.json`. Fails if >4096 regions (`map.cjs:8`) or if
   the map shifts mid-scan (`map.cjs:11-12`).
2. **`app/inspect-mounts.cjs`** — re-verifies four SDK function byte
   signatures from `shared/sdk-layout.json`, then walks the SDK's intrusive
   mount-table linked list at `sdk + mountTableOffset`
   (`inspect-mounts.cjs:14-17`), reads each accessor/implementation/service
   object, and dumps `app/mounts.json` with raw hex of every object
   (`inspect-mounts.cjs:21-37`). Only `save`/`tmp` get deep vtable capture
   (`inspect-mounts.cjs:28`).
3. **`cleanup-scratch.cjs`** (pipeline stage, lives outside app/ but is pure
   app-layer) — clones the app's `save` (and `tmp`) mount via
   `app/mounted-save.cjs`, lists `/`, deletes leftover `NS2_GAP*` scratch
   files from prior launches (`cleanup-scratch.cjs:31-44`).
4. **`app/qualify.cjs`** — the real gate. Creates a `Session`
   (`app/session.cjs:12`) of 0x80000 bytes (`qualify.cjs:13`), which:
   - byte-verifies the six core SDK helpers (`session.cjs:62-65`),
   - allocates the session arena via the SDK `allocate` function using a
     scratch slot at `scratch+0x5300` (`session.cjs:67-77`),
   - then qualifies: multipart transfer + console-side SHA-256 cross-check
     (`qualify.cjs:21-26`, `filesystem.cjs:91-101`), light-event
     init/signal/wait (`qualify.cjs:29-30`, `events.cjs`), counter-frequency
     verify (`timing.cjs:8-29`), core-affinity mask read
     (`affinity.cjs:26-37`), and finally spawns an owned native worker thread
     (`native-worker.cjs:53-68`) that runs a 4-call batch — event wait,
     `GetCurrentThread`, `GetCurrentCoreNumber`, and a memcpy with a
     dynamically loaded length (`qualify.cjs:31-36`) — pins it to the lowest
     allowed core (`qualify.cjs:40-41`), signals, joins
     (`native-worker.cjs:78-100`), and verifies all results
     (`qualify.cjs:44-48`).

After `qualify` passes, the app layer is done; stages 2-4/4 (`acquire`,
`retained`, `ro`, `process`) build on `Session`, `domain.cjs`,
`filesystem.cjs`, `mounted-save.cjs`, and the worker/event/affinity helpers.

---

## 2. SmileBASIC-specific assumptions

### 2a. Wire-protocol / HELLO validation (lib/)

| File:line | Assumption | Civ7 impact | Severity |
|---|---|---|---|
| `lib/connection.cjs:86-88` | `got == main+0x9c92f0`, `memmove == sdk+0x5872f0`, `sdkCrc32 == 3925528160`, `scratchBytes == 0x80000` | Hardcoded to SmileBASIC 4's main/sdk builds. Civ7 HELLO is rejected at pairing; nothing else runs. | **blocker** |
| `lib/connection.cjs:75` | HELLO word[2] == 2 (Switch 2) | Fine — CivSwitch is Switch 2 too. Keep. | reusable |
| `lib/native.cjs:7` | `SDK_BYTES = 0x5e1000` bounds every sdk-relative offset | Civ7 sdk .text is 0x602000 (`dump/`); offsets in `[0x5e1000, 0x602000)` are wrongly rejected. | **blocker** (parameterize) |
| `lib/native.cjs:41` | Padding call uses `offset 0x5872f0` (memmove) | Wrong function in Civ7 sdk → arbitrary code execution at a bad address. | **blocker** |
| `lib/native.cjs:84` | `svcQueryMemory` wrapper at sdk+0x158314 | Wrong offset. Civ7 equivalent verified at sdk-text+0x168B0C (BRIDGE-CONTRACT §1). | **blocker** |
| `lib/native.cjs:113` | `memcpy` at sdk+0x586fb0 (used for every read) | Wrong offset. | **blocker** |
| `lib/native.cjs:127` | `memmove` at sdk+0x5872f0 (used for every write) | Wrong offset. | **blocker** |
| `lib/bridge.cjs:74` | Idle heartbeat calls memmove sdk+0x5872f0 | Wrong offset (same constant, third place). | **blocker** (same fix) |
| `lib/qualify.cjs:8-9` | sdk mapping is exactly 0x5e1000 bytes, type 3, perm R-X | Civ7 sdk .text region is 0x602000; type/perm should hold but size check fails. | **blocker** |
| `lib/qualify.cjs:10-11` | CRC-32 function at sdk+0x71310; expected CRC 3925528160 over 0x5e1000 bytes | Both wrong for Civ7; needs Civ7 crc32 location (or drop CRC, rely on per-function byte checks). | **blocker** |
| `lib/qualify.cjs:31-41` | Activity-report fn at sdk+0x1b18a0 with exact bytes `0020009121088052e6401014`; controller getter at sdk+0x1aba00; vtable at sdk+0xccca90 with entry at +0x120 | Entirely SmileBASIC `nn::gmd`/app-controller layout. No Civ7 equivalent guaranteed. | **blocker** — replace or remove keep-awake |
| `run.cjs:70-73, 197-204` | `START(...)` BASIC command and SmileBASIC console instructions | UX only; CivSwitch connects out from its own loader (TCP :9026 per contract). | must-adapt (cosmetic/flow) |
| `run.cjs:15` | Port 39380 | Fine. | reusable |

### 2b. SDK function tables (shared/ + app/ JSON, all baked-in SmileBASIC bytes)

| File | Contents | Severity |
|---|---|---|
| `shared/sdk-functions.json` | allocate +0x577710, free +0x55b360, getService +0x140510, send (svcSendSyncRequest) +0x15845c, close +0x1583ec, memset +0x5875a0, socket +0x140d40, connect +0x140c50, closeSocket +0x140d90, fcntl +0x140e80, poll +0x140dd0, errno +0x1410b0 — each with full instruction bytes | **blocker** — every offset must be re-derived from `dump/` (workstream B). Note: CivSwitch already wraps sockets console-side, so socket/connect/closeSocket/fcntl/poll/errno may be droppable from the PC engine if nothing PC-side calls them (only `sdk-functions.json` itself lists them; grep shows no engine caller besides session's core six). |
| `shared/sdk-layout.json:2` | `mountTableOffset = 0xd1c8a0` + 4 verified mount-related functions | **blocker** for inspect-mounts/mounted-save; Civ7's mount table offset must be found in the dump (contract §1 warns string xrefs may fail — use pattern analysis). |
| `app/thread-code.json` | 12 functions: create +0x1328e0, join +0x132d20, exit +0x132bb0, current +0x129450, longjmp +0x5b8674, loadTable +0x4bd90, call4 +0x338ea8, saveResult +0x272270, saveResult64 +0x18bc10, tryWait +0x129510, tryWaitImplementation +0x12a5e0, sleep +0x129500 | **blocker** — the whole worker-thread machinery keys off these exact bytes. |
| `app/event-code.json` | LightEvent initialize/finalize/wait/tryWait/signal/clear (+0x1248b0..+0x124a10) + svcWaitForAddressLight/svcSignalToAddressLight wrappers +0x158524/+0x15852c | **blocker** (offsets), mechanics generic. |
| `app/timing-code.json` | tick +0x129640, frequency +0x129670, priority +0x1294c0 | **blocker** (offsets). |
| `app/hash-code.json` | nnSdk GenerateSha256Hash at +0x4cc0 | **blocker** (offset); used by every verified file read (`filesystem.cjs:91-101`). |
| `app/sdk-proxy-code.json` | FS proxy getter +0xb3ec0, global at +0xd1c8e0 | **blocker** for `mounted-save.cjs:42-46` (cloneMountedRoot). |
| `app/thread-scheduling-reference.json` | pthread_get/setaffinity_np +0x133d40/+0x133de0, get/setschedparam/prio, nn::os core-mask getters — full bytes | **blocker** (offsets). |
| `app/compat-affinity-reference.json` | GOT slot +0xd07f88, nnSdk import stub +0x5c3a50, nnCompatThin wrapper +0x7970, `symbolOffsetFromTarget` 135489, "ANDs mask with 7" | **blocker** — assumes the app links `nnCompatThin`. Civ7 (modern SDK game) almost certainly does not have this compat module; the whole `affinity.verify` path (`affinity.cjs:16-23`) must be redesigned. |

### 2c. Hardcoded offsets inside app/ code

| File:line | Assumption | Civ7 impact | Severity |
|---|---|---|---|
| `app/rpc.cjs:14, 45` | "sdk function" range = `[sdk, sdk+0x5e1000)`; outside falls to the gated `callAddress` path | Civ7 sdk .text is 0x602000; calls into the top 0x21000 bytes take the wrong path or fail. | must-adapt (one constant) |
| `app/qualify.cjs:35` | Inline memcpy at `live.sdk + 0x586fb0` in the worker call batch | Wrong function address in Civ7 sdk. | **blocker** |
| `app/native-worker.cjs:46, 73` | Same 0x586fb0 for worker snapshot copy/restore | Wrong offset. | **blocker** (same fix) |
| `app/qualify.cjs:13` | Session arena 0x80000 bytes | Size fine, but Civ7's heap must actually yield 512 KiB via the located `allocate`; busy game heap may fragment. | tunable |
| `app/timing.cjs:6` | `nativeFrequencyCode` at compat-module +0x13d6f0 with exact bytes | Belongs to SmileBASIC's bundled compat module. | **blocker** |
| `app/timing.cjs:13-18` | Compat module = the *unique* R-X region of exactly 45989888 (0x2bdc000) bytes in `memory-map.json` | Civ7 has many large R-X regions; uniqueness by exact size will fail. | **blocker** — needs a different discriminator, or drop the cross-check |
| `app/timing.cjs:25` | Native counter 31250000 Hz, legacy SDK reports 19200000 Hz | 31.25 MHz is Switch 2 hardware (generic); the "legacy SDK lies" behavior is SmileBASIC-sdk-specific. | must-adapt |
| `app/inspect-mounts.cjs:28` | Only mounts literally named `save`/`tmp` get deep capture | nnSdk mount-name convention likely holds, unverified; list cap 32 at line 18. | must-adapt (verify on hardware) |
| `app/mounted-save.cjs:25` | SDK session-manager state: `state[8]==0x800`, `state[0x5c]==3` | nnSdk-internal layout for this SDK version; Civ7's SDK may differ. | must-adapt |
| `app/mounted-save.cjs:6-11` | A mount named `save` exists and was captured this boot | Civ7 might not have `save` mounted at exploit time. | **blocker** for stage-2 acquisition if absent (feeds workstream D) |
| `app/filesystem.cjs:9` | FS path commands limited to {7,8,9,11,12,14} | Horizon fs command IDs — console-agnostic. | reusable |
| `app/filesystem.cjs:14-17` | X-descriptor packing assumes 39-bit addresses | Horizon-generic. | reusable |
| `app/filesystem.cjs:68, 82` | Read caps 0x40000 (0x400000 bulk) | Self-imposed vs. arena size; fine. | tunable |
| `app/filesystem.cjs:126-137` | Directory entry stride 0x310, <=4 entries/read, <=128 entries | Horizon FS entry format — generic. | reusable |
| `app/session.cjs:67` | `scratch+0x5300` is free, ordinary owned RW memory | Depends on the console bridge replicating bootstrap.bas scratch layout (contract sec.2: input at +0x40000, output window +0x4030..+0xc040; 0x5300 sits inside the output window but is only clobbered by large reads, which never target it). | must-adapt (bridge-side, workstream A) |
| `app/session.cjs:69-71, 79-81` | Allocation lands in a type-5, perm-3, attribute-free region | Horizon memory-type semantics — generic; but Civ7 heap is noisy, allocation may fail. | must-adapt (heap behavior) |
| `app/session.cjs:93` | Handles `< 0xffff8000` are valid | Horizon handle encoding — generic. | reusable |
| `app/map.cjs:7-8` | 2^39 address space, <=4096 regions | Civ7's map mutates during the scan (streaming) and trips the abort at `map.cjs:11-12`. | must-adapt (see sec.5) |
| `app/affinity.cjs:29-32` | `sdkMask subset of processMask`, both < 2^32 | Generic logic, but the mask source is the AND-7 compat wrapper; Civ7 needs a different path. | must-adapt |
| `shared/frames.cjs:4, 53` | `SDK_SIZE = 0x5e1000`; every worker call target must be inside `[sdk, sdk+SDK_SIZE)` | Rejects legit Civ7 sdk functions above 0x5e1000. | must-adapt (parameterize) |
| `shared/frames.cjs:23` | Dynamic-argument loads use memcpy at sdk+0x586fb0 | Wrong offset. | **blocker** (same constant fix) |
| `shared/frames.cjs:31-34` | Frame geometry (tables 0x100/call, stack 0x140/call, cap 0x2000000) | Self-contained layout — generic. | reusable |
| `pipeline.cjs:48` | Retained-memory capture identified by length 0x4d8000 | Later-stage constant keyed to SmileBASIC heap behavior. | must-adapt (workstream D) |
| `pipeline.cjs:55` | `layout.sdk + 0x12a0` passed to ro/test-sm | Later-stage offset keyed to this sdk build. | must-adapt (workstream D) |

### 2d. Timing / threading constants

| File:line | Constant | Civ7 impact | Severity |
|---|---|---|---|
| `shared/stages.cjs:7` | 10-min per-stage timeout | Fine. | tunable |
| `app/native-worker.cjs:78, 107` | join timeout 15000 ms, 10 ms poll | A loaded Civ7 process may delay a pinned worker past 15 s. | tunable (raise) |
| `lib/bridge.cjs:70-76` | heartbeat every 5 s; activity report after 30 s idle | Keep-awake target is SmileBASIC-specific (sec.2a); interval itself fine. | must-adapt (target) |
| `lib/connection.cjs:109, 117` | 10 s pairing read timeout, 120 s op timeout | Generous; OK even on a loaded game thread. | tunable |
| `shared/rpc.cjs:20` | 180 s HTTP bridge timeout | Fine. | reusable |
| `app/qualify.cjs:21` | 0x10002-byte transfer challenge | Fine. | reusable |
| `shared/rpc.cjs:39, 42, 51, 53` | 64 MiB transfer cap, 0x80000 chunking | Fine. | reusable |

---

## 3. PC-side files that must change for the port

| File | Change |
|---|---|
| `engine/lib/connection.cjs` | Parameterize `parseHello` (lines 84-88): accept Civ7 got/memmove deltas and sdk CRC from a port config instead of hardcoded SmileBASIC values. |
| `engine/lib/native.cjs` | Replace `SDK_BYTES` (line 7) and the baked offsets (0x5872f0 lines 41/127, 0x586fb0 line 113, 0x158314 line 84) with config-driven values. |
| `engine/lib/bridge.cjs` | Line 74 idle-call offset from config; make `keepAwake` optional if no Civ7 activity-report equivalent exists. |
| `engine/lib/qualify.cjs` | Rewrite for the Civ7 build (sdk size 0x602000, new CRC, drop or replace the activity-report/vtable/controller chain at lines 31-42). |
| `engine/shared/sdk-functions.json` | New Civ7 file (workstream B emits `port/sdk-functions.civ7.json`, same schema). Socket-family entries likely droppable: only allocate/free/getService/send/close/memset have engine callers (`session.cjs:62`). |
| `engine/shared/sdk-layout.json` | New mountTableOffset + verifiedFunctions for Civ7 sdk. |
| `engine/shared/frames.cjs` | Parameterize `SDK_SIZE` (line 4) and dynamic-load memcpy offset (line 23). |
| `engine/switch2/app/rpc.cjs` | Parameterize the 0x5e1000 sdk range (lines 14, 45). |
| `engine/switch2/app/qualify.cjs` | Replace inline 0x586fb0 (line 35) with the shared constant. |
| `engine/switch2/app/native-worker.cjs` | Same for lines 46, 73. |
| `engine/switch2/app/timing.cjs` | Replace module identification (lines 13-18) and `nativeFrequencyCode` (line 6); possibly drop the native/legacy cross-check (line 25). |
| `engine/switch2/app/affinity.cjs` | Replace the nnCompatThin GOT/wrapper verification (lines 16-23) with a direct path for Civ7's core-mask getter. |
| `engine/switch2/app/inspect-mounts.cjs` | New layout JSON covers offsets; possibly widen the mount-name set (line 28). |
| `engine/switch2/app/mounted-save.cjs` | Verify/replace session-manager layout check (line 25) and sdk-proxy-code.json contents. |
| `engine/switch2/app/*.json` (thread-code, event-code, timing-code, hash-code, sdk-proxy-code, thread-scheduling-reference, compat-affinity-reference) | Regenerate all from `dump/` (workstream B). |
| `run.cjs` | Replace BASIC connect UX (lines 70-73, 197-204) with CivSwitch connect-out flow; engine mechanics unchanged. |

Unchanged: `shared/ipc.cjs`, `shared/domain.cjs`, `shared/rpc.cjs`,
`shared/stages.cjs`, `app/map.cjs`, `app/domain.cjs`, `app/filesystem.cjs`,
`app/session.cjs`, `app/events.cjs`, `app/worker.cjs`, `app/bulk-transfer.cjs`,
`cleanup-scratch.cjs` logic.

---

## 4. Console-agnostic Horizon mechanics (reusable as-is)

- `shared/ipc.cjs` — CMIF packet/response framing, A/B/X descriptor encoding, SFCO parsing, 39-bit address packing. Pure Horizon.
- `shared/domain.cjs` — CMIF domain convert/invoke/close-object framing. Generic.
- `app/domain.cjs` — fsp-srv open, SetCurrentProcess (cmd 1), ConvertToDomain (control 0), OpenStorage (200/202), CopyObject, GetSize. Standard Horizon FS IPC from any process that can reach fsp-srv.
- `app/filesystem.cjs` — read-only FS commands 7/8/9/11/12/14, ReadFile/ReadStorage/FileGetSize/ReadDirectory with receive descriptors, directory entry format. Stock Horizon FS.
- `app/map.cjs` — svcQueryMemory walk of the 39-bit space. Generic (region cap/mutation caveat in sec.5).
- `app/session.cjs` — arena ownership model, handle tracking, CMIF `ipc()`, cleanup discipline. Generic once `sdk-functions.json` is swapped.
- `app/events.cjs`, `app/native-worker.cjs`, `shared/frames.cjs` geometry — nn::os LightEvent and pthread mechanics are Horizon SDK semantics; only the byte-signature JSONs are build-specific.
- `lib/bridge.cjs` HTTP serialization, `lib/connection.cjs` socket framing, `shared/stages.cjs` stage runner, `shared/rpc.cjs` bridge client — transport plumbing, platform-agnostic.

---

## 5. Risks running from Civ7 instead of SmileBASIC

1. **Memory-map mutation during `map`.** Civ7 streams assets and maps/unmaps regions continuously; `map.cjs:11-12` aborts the whole pipeline if any region boundary shifts mid-scan. Idle SmileBASIC is essentially static. Mitigation: retry loop or tolerate-and-rescan; the 4096-region cap (`map.cjs:8`) is also closer to being hit.
2. **Heap contention.** `Session.initialize` demands a fresh 0x80000-byte type-5 RW allocation from the game's allocator (`session.cjs:74-81`). A fragmented game heap may fail it, and later stages allocate far more (sizing belongs to workstream D).
3. **Thread pressure.** The worker machinery calls the sdk `pthread_create` inside a process already running dozens of threads. The 15 s join timeout (`native-worker.cjs:78`) can be exceeded under load, and the affinity path (`affinity.cjs`) assumes a discoverable available-core mask that Civ7's SDK exposes differently (no nnCompatThin AND-7 wrapper).
4. **RPC loop starves or is starved.** Every native call is a serialized TCP round trip driven from the CivSwitch loader context. If that context shares a core/timing budget with the game, per-call latency grows; the 120 s op timeout (`lib/connection.cjs:117`) papers over it, but 10-min stage timeouts may not for the map stage (one round trip per region).
5. **Save-FS availability and size.** `mounted-save.cjs` assumes a mounted `save` (maybe `tmp`) with the exact nnSdk session-manager layout (`mounted-save.cjs:25`). Civ7's save may be huge, unmounted at exploit time, or managed by a different SDK revision — this gates stage-2 acquisition (feeds workstream D).
6. **Keep-awake gap.** `lib/qualify.cjs:31-42` finds SmileBASIC's activity-report interface to prevent idle sleep. No Civ7 equivalent is identified; low risk while the game is running, unverified.
7. **Stale code-cache.** `session.cjs:29-40` caches verified instruction bytes keyed by `session + sdk base`; per-boot run dirs (`fs.mkdtemp`, `run.cjs:190`) already prevent cross-target reuse — keep it that way.
8. **Module identification by size.** `timing.cjs:13` finds a module by exact byte size; that heuristic class breaks on a multi-module game and must become content-based (bytes/CRC) if kept at all.
