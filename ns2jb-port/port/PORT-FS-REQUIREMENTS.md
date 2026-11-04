# Workstream D — What the fs/ro/pm stages require from the HOST APP process

Scope: `ns2jb-main/engine/switch2/{memory,retained,ro,process,tools}/*`, `acquire.cjs`,
`pipeline.cjs`, `cleanup-scratch.cjs`, `firmware-dump.cjs`, plus the app-layer helpers in
`engine/switch2/app/*` that the fs stages directly consume. All line references are to the
pristine tree under `ns2jb-main/`.

Question answered: which of these requirements can the **Civ 7 process** (driven through
CivSwitch: full-process arbitrary R/W + native calls + sockets) plausibly satisfy, and which
need runtime probing?

---

## 1. The exploitation mechanism in plain terms

### 1.0 What the host app provides at the bottom

Everything the engine does on-console is expressed through a PC-driven RPC into the host
app process (native calls, memory R/W of the app, `svcQueryMemory`, `SendSyncRequest`,
`CloseHandle`, `GetService`, `memset/memcpy`; `engine/switch2/app/session.cjs:45-46,97-109`,
`engine/switch2/app/rpc.cjs:10-54`). On top of that the engine builds **native worker
threads inside the app process**: it fabricates a thread whose entry is the SDK's own
`longjmp`, with a fully crafted register/stack "frame" in owned memory, so the thread
executes a pre-programmed sequence of SDK calls (event waits, ns-precision sleeps,
`SendSyncRequest` IPCs, counter ticks) without any PC round-trips
(`engine/shared/frames.cjs:10-72`, `engine/switch2/app/native-worker.cjs:32-68`). This is
why the race choreography is immune to network latency: the PC only signals one gate event
(`probe-reserved-gap.cjs:406`).

### 1.1 Setup: borrowing the app's FS identity

- The engine walks the host app's **nnSdk mount table** (an intrusive linked list in the
  app's sdk module globals) and verifies each mount's accessor/service vtables by exact
  instruction-byte match (`app/inspect-mounts.cjs:8-39`, `engine/shared/sdk-layout.json`).
  It requires mounts named **`save`** and **`rom`**.
- Through the app's *borrowed* save-filesystem session it issues `CopyObject`
  (CMIF control 1) to obtain its own client handles to the app's mounted save FS
  (`app/mounted-save.cjs:32-38`, `app/domain.cjs:43-46`). The app's own mounts and sessions
  are never closed (`app/mounted-save.cjs:1`, `app/inspect-mounts.cjs:1`).
- It clones the app's mounted **RomFS IStorage** the same way (`memory/mounted-rom.cjs:7-41`).
- It opens its **own `fsp-srv` session** and calls `Initialize` (cmd 1) with the app's PID
  (`probe-reserved-gap.cjs:195-196`, `app/session.cjs:85-96`).

### 1.2 The corruption primitive (normalized-path bug)

- On the cloned save FS it creates a scratch tree (`/NS2_GAP_<ts>`), a 16 MiB
  `commit_data` file, a 1-byte canary file at a long normalized path, and several nested
  "extent" directories (`probe-reserved-gap.cjs:44-46,203-229`).
- Each **wave** writes the full 16 MiB to `commit_data` (one IPC with a 16 MiB send buffer,
  `probe-reserved-gap.cjs:337-341`), then launches **13 native worker threads**, pinned
  round-robin over the app's allowed cores, gated on one manual-reset event
  (`probe-reserved-gap.cjs:393-401`). When the PC signals the gate, the workers issue
  13 concurrent `SendSyncRequest`s to fsp-srv with nanosecond-staggered start delays
  (0 / 300 / 350 / 450 / 550 / 650 / 1700 / 2000 / 2150 / 2800 µs, plus event-chained
  guards; `probe-reserved-gap.cjs:299-326`).
- The 13 requests have fixed roles (`probe-reserved-gap.cjs:299-300`): `commit`,
  `hole` (IStorage read with a 1.5 MiB receive buffer), four `tailN` (cmd 1002 with 0x800
  path pieces), `canary` (GetEntryType on the owned canary path), two `filler`s and two
  `guard`s (cmd 5 two-path requests on deliberately absent long paths), `release`
  (CloseObject of a reserved 59-object domain group), and `trigger`.
- The **trigger** sends GetEntryType (cmd 7) with a 0x2441-byte path delivered as **five
  separate 0x800-byte X-descriptor pieces** that the FS server reassembles
  (`probe-reserved-gap.cjs:343-380`). For the positive profile the path is mostly `'B'`
  filler and embeds `/..\` (backslash) plus a chosen directory name at offset 0x2340
  (`probe-reserved-gap.cjs:355-362`). The FS path normalizer mishandles this
  already-overlong multi-buffer input: the normalized path copy occupies a heap buffer
  whose lifetime is tied to the pending request, while the concurrently running `release`
  request frees a precisely sized reservation group (59 x 208 bytes,
  `probe-reserved-gap.cjs:98-137`) so the still-pending path buffer is reused as a freed
  heap allocation. Held requests (`canary`, fillers, guards) keep their buffers alive; the
  window is qualified only if every other request was pending for the whole trigger
  execution (`memory/wave-overlap.cjs:5-18`) with >= 300 µs of receive-order margin
  (`probe-reserved-gap.cjs:502-503`).
- A "native guard" worker copies live ordering flags into the trigger's first byte before
  the kernel reads it, turning the trigger into a harmless empty path if the required
  receive order did not hold — this is what makes retries survivable
  (`probe-reserved-gap.cjs:313-319,335-336`).

### 1.3 From poisoned path to poisoned IStorage → arbitrary FS R/W (confirms the task's reading)

- The overwrite target is an **FS content-cache entry** for the app's *own RomFS content
  storage*. The engine opens that storage on its own fsp-srv root with cmd 200
  (`probe-reserved-gap.cjs:230,594`) — an ordinary `IStorage` whose reads/writes go through
  the FS-side block cache. Path bytes planted by the trigger land in the cache-entry
  metadata; by repeated waves with byte-exact "field copies" (`copyField`,
  `probe-reserved-gap.cjs:605-646`) the engine writes a crafted **cache header** whose
  bytes must be valid UTF-8, must not contain `0x00`, `/` or `\`, and must encode a
  *signed negative* cache offset: `{i64 entryOffset, u64 range, u8 flags[4], u64 base}`
  chosen so that `base + readOffset − entryOffset == target` and the signed offset selects
  cache bucket 0 (`memory/signed-cache-plan.cjs:21-77`, planner `plan()` at :79-100;
  NUL bytes are produced by successive shorter copies, `memory/cache-address-plan.cjs:4-14`).
- After the header is planted, **`IStorage` command 0 (Read) at the chosen logical offset
  copies FS-process memory at `target` into the app's receive buffer, and command 1
  (Write) writes app-supplied bytes into FS memory at `target`** — the task's reading is
  correct: commands 0/1 of the poisoned storage are arbitrary R/W over a remapped
  0x4000 window of the FS process (`probe-reserved-gap.cjs:571-580` (read),
  :918-925 (write), the 16-byte R/W/restore proof at :983-1006,
  `memory/fs-memory-control.cjs:72-144`). `IStorage` cmd 5 (OperateRange/Invalidate) is the
  restore path (`probe-reserved-gap.cjs:663-682`).
- Because each retarget needs another path-corruption wave, the engine then **promotes**
  the primitive: it finds the storage's own cache array/owner in FS memory, installs a
  permanent two-bucket control+data descriptor pair with the bucket count zeroed, giving a
  **steady-state, no-further-corruption** FS R/W endpoint ("retained memory",
  `retained/retained-memory.cjs:205-314`, install via `ro/install-retained.cjs`). From then
  on, FS memory R/W is plain serialized IPC (`tools/fs-memory.cjs:122-172`).

### 1.4 Escalation: owned fsp-srv root, BIS, Loader root, RO/pm

- With FS R/W the engine locates its own fsp-srv root object in FS's domain manager
  (verified by a clone-count challenge, `ro/objects.cjs:38-60`) and **overwrites the PID
  fields of the root and its nca/save backends to 1** (`tools/fs-root-pid.cjs:26-66`).
  FS now treats the app's session as privileged: `OpenBisStorage` (cmd 12) and
  `OpenBisFileSystem` (cmd 11, USER=30/SYSTEM=31) become callable
  (`memory/fs-root-control.cjs:87-159`). It also opens `OpenSystemDataUpdateEventNotifier`
  (cmd 510) (`ro/control.cjs:104-116`) and uses the notifier's FS-side backend object as a
  **handle exporter**: overwriting the handle field in FS memory makes `GetEventHandle`
  return a duplicate of *any* FS-local handle (`ro/export-handle.cjs:7-32`).
- It finds FS's own initialized **sm: client session** in FS memory, exports it, and uses
  it to open `pm:shell`, `pm:dmnt`, `ncm` (`ro/test-sm.cjs:6-35`, `ro/control.cjs:156-191`).
- It locates **Loader's** root inside FS (from a boot-time heap capture plus live
  structural checks, `ro/layout.cjs:36-83`), swaps one of its own domain entries to
  reference Loader's root object, and issues `CopyObject` to obtain an owned handle to it
  (`ro/copy-loader-root.cjs:53-64`). Through that handle it opens **CodeFS** of a chosen
  system title and captures `main.npdm` (`ro/files.cjs:198-235`).
- **Donor**: it writes the payload `main` + that title's `main.npdm` into the app's save
  FS root (`ro/files.cjs:79-196` — again only the app's writable save mount is needed).
- **Launch**: it parks FS's Loader server session (rewiring its wait handle onto the owned
  notifier event), steps Loader's requests one at a time, and at the second CodeFS mount
  request for the target title swaps the domain entries so the launched process's code
  mount resolves to the donor save FS (`ro/gate.cjs:38-102`, `ro/launch.cjs:68-126`).
  `pm:shell` `LaunchProcess` (flags 0x10) then loads the payload binary from the app's save
  data as if it were the system title's code; `pm:dmnt` starts it and the original `ro`
  process is terminated (`ro/runtime.cjs:19-54`). The payload is a tiny svc-only server
  that registers `ro:dmnt` (`ro/payload/main.c`, `ro/payload/start.S`).
- **ro/pm code execution**: via the payload's `ro:dmnt`, the engine maps process memory
  (svcMapProcessCodeMemory etc., `process/client.cjs:95-111`), runs a test function inside
  the *app* process at a free RX alias (`process/qualify.cjs:38-58`,
  `process/test-function.S`), and proves FS code execution by patching 16 bytes of FS's
  `GetEventHandle` to return a nonce, twice, with full restore
  (`process/fs-execute.cjs:38-81`).

Nothing after §1.3 needs new *app-process* capabilities except where noted below — the
ro/pm work runs against FS memory and kernel SVCs issued from app-owned threads.

---

## 2. Requirements checklist (host app process)

Legend: **HARD** = exploit cannot run without it; **TUNABLE** = SmileBASIC-specific value
that must be re-derived for Civ7 (workstream B territory) but is not fundamentally gated.

### 2.1 Console-side bridge & memory

| # | Requirement | Evidence | Class |
|---|---|---|---|
| R1 | Arbitrary R/W + native 4–6-arg calls in the app process, serialized RPC | `app/session.cjs:45-46`, `app/rpc.cjs:20-31`; CivSwitch provides | **TUNABLE** (given) |
| R2 | A page-aligned **owned RW allocation of 0x2400000 bytes (36 MiB)** in the app, type-5 memory verified by `svcQueryMemory`; worker frames, the 16 MiB write buffer, the 2 MiB read buffer, and snapshots all live inside it at fixed offsets up to `base+0x2200000+0x2000` | connect size `0x2400000` (`probe-reserved-gap.cjs:26`), `app/session.cjs:74-83`, layout constants `probe-reserved-gap.cjs:38-52`, `ro/worker-control.cjs:45`, `ro/process-test.cjs:10` | **HARD** (shrinkable only with re-layout; the 16 MiB `writeSize` at `probe-reserved-gap.cjs:48` dominates) |
| R3 | The 0x80000-byte HELLO scratch region | `BRIDGE-CONTRACT.md` §2 | **TUNABLE** |
| R4 | `svcQueryMemory`, `svcCloseHandle`, `svcSendSyncRequest(buffer,size,handle)`, and a GetServiceHandle equivalent reachable as in-sdk call targets | `shared/sdk-functions.json` (`send`,`close`,`getService`,`allocate`,`free`,`memset`), `app/session.cjs:85-99` | **TUNABLE** (Civ7 sdk gadget hunt; bare `svc;ret` gadgets suffice for SVCs) |

### 2.2 Threads, affinity, events, timing

| # | Requirement | Evidence | Class |
|---|---|---|---|
| R5 | Create **13 concurrent native threads** from crafted frames (entry = SDK `longjmp`, register/stack state in owned memory), restart them per wave, poll-join via `tryWait`; plus 1 extra worker for the ro/launch stages | `app/native-worker.cjs:32-100`, `shared/frames.cjs:10-72`, `probe-reserved-gap.cjs:299-326,393-401`; verified function list `app/worker.cjs:6-12` | **HARD** (needs pthread_create/join + longjmp + the 5 gadget-shaped SDK functions in Civ7's sdk) |
| R6 | Pin each worker to a chosen core: `pthread_getaffinity_np`/`pthread_setaffinity_np`, `nn::os::GetThreadAvailableCoreMask`, `GetCurrentCoreNumber`; ≥2 allowed cores, up to 13 used round-robin | `app/affinity.cjs:8-76`, pinning loop `probe-reserved-gap.cjs:400` | **HARD** (any game has a usable core mask; Civ7's mask read at runtime) |
| R7 | In-process manual-reset light events (init/wait/signal/clear/finalize) living in owned memory | `app/events.cjs:1-40`, gates at `probe-reserved-gap.cjs:280-283` | **TUNABLE** (find Civ7 equivalents) |
| R8 | Nanosecond sleep callable from workers; monotonic counter readable from workers; the engine **hard-checks the counter frequency == 31250000** (Switch 2 hardware constant, so it transfers) | delays `probe-reserved-gap.cjs:301`, `app/timing.cjs:6,23-25`, worker `sleep` in `app/worker.cjs:7` | **TUNABLE** for offsets; hardware constant is safe |
| R9 | The game must not disturb the FS heap during a wave: exact allocation-counter restoration is checked per wave (`after[5] + 13616 === before[5]`); any extra FS activity from the host app invalidates the run | `probe-reserved-gap.cjs:92-97,447,459-465` | **HARD, Civ7-specific risk** — see §3/§4 |

### 2.3 Filesystem mounts and fsp-srv usage

| # | Requirement | Evidence | Class |
|---|---|---|---|
| R10 | App has an **nnSdk-mounted save-data FS** named `save` in the mount table; borrowed (never closed) and cloned via `CopyObject`; two independent clones used as `saved`/`temporary` | `app/mounted-save.cjs:6-38`, `probe-reserved-gap.cjs:192-194` (`mountPlan {save:'save', temporary:'save'}`) | **HARD** |
| R11 | That save FS has **> 0x1410000 bytes (~20.4 MiB) free** (`writeSize 0x1000000 + 0x400000 + 0x10000`) and supports: CreateFile(0), DeleteFile(1), CreateDirectory(2), DeleteDirectoryRecursively(4), GetEntryType(7), OpenFile(8), OpenDirectory(9), Commit(10), GetFreeSpace(11); IFile Read(0)/Write(1) with a **single 16 MiB IPC send buffer**, GetSize(4); 0x301 single-descriptor paths and multi-descriptor reassembly of a 0x2441-byte path | `probe-reserved-gap.cjs:203-229,337-341`; `shared/ipc.cjs:15-35`; README.md:4 | **HARD** (free space is the big Civ7 unknown) |
| R12 | App has its **RomFS mounted** (name `rom`) in the SDK mount table with the expected accessor/service shapes, so its IStorage can be borrowed and cloned; the same storage must also be openable via fsp-srv cmd 200 on the app's own initialized root | `memory/mounted-rom.cjs:7-41` (requires `rom` and `save`), `probe-reserved-gap.cjs:230` | **HARD** (Civ7 must mount RomFS via nn::fs — probe) |
| R13 | Own-content storage size **>= 0x1600000 (22 MiB)**: alias offset 0x1400000 + cacheReadSize 0x200000 must fit, and content at 0x1400000 must differ from offset 0 | `probe-reserved-gap.cjs:231-234,567,587-591,652` | **HARD** (any full game's RomFS is GiB-scale — fine *if* R12 holds) |
| R14 | ~20+ simultaneous fsp-srv session handles + one domain with **59 reserved objects** (cmd 1200) + 1 wrapped group; clones of root/save/notifier; fsp-srv per-process session budget must also absorb the game's own sessions | `probe-reserved-gap.cjs:98-137,275-279`; domain cap 0x4000 `ro/layout.cjs:25` | **HARD** (well under system limits) |
| R15 | fsp-srv commands usable from an ordinary app session: Initialize(1, pid), own-content open (200), allocation counters (1009), manager reservation (1200), `OpenSystemDataUpdateEventNotifier` (510), domain controls 0/1/2, IStorage 0/1/4/5 | `probe-reserved-gap.cjs:94,106,196,230,298`; `memory/fs-root-control.cjs:58-66`; `ro/control.cjs:108` | **HARD** (same firmware ⇒ same gating; re-verify once) |
| R16 | IPC mechanics: CMIF with X-descriptor (map-alias) buffers pointing **anywhere in the app's 39-bit address space** (the owned allocation), ≤2 path descriptors ≤0x800 each per message, receive buffers up to 0x200000, send buffers up to 0x1000000, PID descriptor, copy handles, domain (HIPC) messages; every request staged on its own 4096 page because the reply overwrites the page | `memory/paths.cjs:4-25`; `probe-reserved-gap.cjs:18,103-105,337-341,378-379`; `shared/ipc.cjs`; `app/domain.cjs:27` | **HARD** (pure kernel/SVC ABI — app-agnostic; CivSwitch already passes buffers by address) |
| R17 | A **free 0x1000 page** in the app address space that RO can map RX and unmap (`freeAddress` chosen by the RO payload scanning the app), and tolerance of that map/unmap | `process/qualify.cjs:38-61`, `ro/process-test.cjs:31-50` | **HARD** (plenty of free VA; probe) |
| R18 | Console-side native SHA-256 (verifies worker frames and file bytes without round-trips) | `app/filesystem.cjs:91-101` (`hash-code.json`) | **TUNABLE** (replaceable by bridge readback + PC-side hash at speed cost) |
| R19 | ProgramId currently hard-checked against SmileBASIC's two title IDs | `process/qualify.cjs:17-18` | **TUNABLE** (patch list) |

### 2.4 Things the task asked about that turned out **not** to be required

- **Cache-storage mount (`MountCache`/`Unmount`, `tmp`)**: `memory/cache-mount.cjs` exists
  but is referenced by *no other file* in the tree and is absent from `pipeline.cjs`. The
  exploit's "cache" is fsp-srv's content cache for the RomFS IStorage, not a `tmp`
  cache-storage mount. The save FS is the only writable mount needed.
- **Thread priorities**: never set — `pthread_create(slot, 0, entry, arg)` with null attr
  (`app/native-worker.cjs:58`); only affinity is controlled.
- **SD card**: explicitly unwanted — README.md:11 says keep the game on internal storage.

---

## 3. Can Civ 7 satisfy each HARD requirement?

| Req | Plausibility for Civ7 | Probe needed |
|---|---|---|
| R2 (36 MiB owned RW) | CivSwitch `malloc` is calloc-backed against the game heap; a 36 MiB contiguous, page-aligned, type-5 RW region must be obtainable. Likely OK on a AAA title's heap (or via heap-growth SVCs), but must be measured. Also verify the game never frees/trims it for the duration of a run (potentially hours). | Try `malloc(0x2400000)` + `svcQueryMemory` for type 5 / perm 3. |
| R5 (13 crafted threads) | Needs pthread_create/pthread_join + `longjmp` + 5 small gadget-shaped functions in Civ7's sdk (6 MiB .text — high probability). Semantics must match exactly; worker frames depend on the register conventions of `loadTable`/`call4`/`saveResult64`/`exit` (`shared/frames.cjs:47-67`). | Gadget hunt in `dump/` (capstone available). **Risk: BTI/PAC** — the frame chain lands via `blr`/ret at arbitrary SDK addresses; every gadget target must be a valid landing pad (`test-function.S` starts with `bti c` for this reason). Verify each gadget's first instruction. |
| R6 (affinity pinning) | Games get a wide core mask; the pthread affinity functions exist in any nnSdk. Fine. | Read `GetThreadAvailableCoreMask` equivalent once. |
| R9 (FS quiet during waves) | **The single most Civ7-specific hazard.** A streaming open-world game issues its own fsp-srv traffic (asset loads, auto-saves, shader caches). Any foreign FS allocation during a wave breaks the exact accounting checks (`probe-reserved-gap.cjs:447,459-465`) or, worse, steals the freed reservation group mid-overwrite. Mitigation: run at a static menu with streaming quiesced; the 30-waves-per-profile retry budget absorbs occasional disturbance. | Measure FS allocation-counter (cmd 1009) stability over minutes with Civ7 at main menu vs in-game. |
| R10 (mounted `save`) | Civ7 keeps save data mounted while running. The shape checks (`app/mounted-save.cjs:12-30`) are SDK-build-specific, so verification bytes must be re-derived for Civ7's nnSdk, but the mechanism (borrow session, CopyObject) is generic. | Walk Civ7's sdk mount list (new `mountTableOffset`); confirm a `save` entry and that its session accepts controls 1/2. |
| R11 (20.4 MiB free save) | **Unknown. Go/no-go gate.** Save-data size is fixed at creation by the game; if Civ7's save FS is small, the 16 MiB `commit_data` file cannot be created (`writeSize` is a compile-time constant at `probe-reserved-gap.cjs:48`; shrinking it changes the heap-shaping geometry and would need full re-qualification). | `GetFreeSpace('/')` on Civ7's save FS via the bridge. **Do this first — it is cheap and decisive.** |
| R12 (mounted `rom`) | Unknown. Many games stream from RomFS and keep it mounted; some use ncm content storages directly. The engine needs both the SDK mount-table entry (for cloning) and cmd 200 on the app's own root. | Walk the mount list; call cmd 200; compare `GetSize` with the RomFS clone. |
| R13 (storage ≥ 22 MiB) | Trivially true for Civ7 if R12 holds. | — |
| R14 (session/handle counts) | Fine: ~20 sessions + 59 domain objects is far below fsp-srv's per-process budget even with the game's own sessions. | Count existing handles if paranoid. |
| R15 (fsp-srv command access) | Same firmware ⇒ same command gating for all game-class processes; the engine already proves these commands work from a retail title (SmileBASIC). Re-verify cmd 1009's 16-counter reply shape once. | One-shot IPC probes. |
| R16 (IPC buffer mechanics) | Pure kernel ABI; CivSwitch already does address-based IPC. The 16 MiB single-descriptor send is the only extreme; it is an ordinary map-alias buffer and the kernel accepts it from any app. | — |
| R17 (free RX-able page) | Free VA is plentiful; RO's mapping authority is target-agnostic (it maps into the app by PID). | — |

Bottom line for §3: **R11 (save free space) and R12 (RomFS mounted via nn::fs) are the two
hard go/no-go gates**; R9 (FS quiescence under a live AAA game) is the hard operational
risk; R5 (thread/gadget availability incl. BTI) is the hard engineering risk. Everything
else is either guaranteed by the firmware or a workstream-B offset hunt.

---

## 4. Timing sensitivity — what is actually raced

1. **The one true race** is the per-wave 13-request choreography into fsp-srv
   (`probe-reserved-gap.cjs:299-409`). Qualification (`hasWindow`, :502-503) requires, all
   measured on-console with the 31.25 MHz counter:
   - `allPending`: every held/through request started before `trigger` and outlived it
     (`memory/wave-overlap.cjs:14-17`) — 13 genuinely concurrent in-flight IPCs;
   - `receiveOrderMarginUs >= 300 µs`: the `hole` receive must finish at least 300 µs
     before `guard1` starts (`probe-reserved-gap.cjs:445,502`);
   - `preReleaseUsed >= 0x2600`: the `release` must have freed >= ~9.7 KiB of the reserved
     group while the path requests were held (:502);
   - `restored`: the FS general-heap counter must return exactly to baseline (+13616 for
     the pin allocation) after the wave (:447);
   - the native abort guard must not have fired (:313-319,502).
2. **Retry budgets**: `waveAttempts = 30` per profile (:21,506-516); field copies need
   2 confirmed accepts within <= 40 tries each (:605-646); the whole acquisition is wrapped
   in `MAX_ATTEMPTS = 3` with the comment "This is flaky right now"
   (`acquire.cjs:13-16`), and a failed acquisition requires a **fresh boot**
   (`acquire.cjs:59`, README.md:96-98).
3. **Observed success factors** (README.md): ~20% per fresh boot at best (README.md:12);
   the 2026-10-21 hardware test passed on the third fresh boot (README.md:140-143);
   ethernet on both ends is mandatory because of timing sensitivity (README.md:9-10);
   game on internal storage, not SD (README.md:11). Note the race itself is
   console-internal once the gate fires — network quality matters because each attempt
   needs dozens of setup waves staged over the RPC (including a 16 MiB upload per wave),
   so jitter/loss inflates wall time and the window in which something else can disturb
   the FS heap. The worker delays (`probe-reserved-gap.cjs:301`) are tuned to FS behavior,
   not to the app, so they should transfer to Civ7 unchanged — but Civ7's background CPU
   load will widen worker start jitter, lowering the per-wave hit rate below the
   SmileBASIC baseline.
4. **Later stages are not races**: the retained endpoint is deterministic
   (`retained/retained-memory.cjs`); the Loader-launch gate is a *stepped* state machine
   with explicit per-request acknowledgement, 30-attempt injection loops and an idle
   deadline (`ro/gate.cjs:58-102`, `ro/launch.cjs:73-79`), not a timing race.

---

## 5. Cleanup / restore obligations and interruption risks

Ordered by severity of the state left behind:

1. **Retained/promoted FS corruption** (worst): once `retained-install` has run
   (`state.promoted = true`, `retained/retained-memory.cjs:227`), FS's cache metadata is
   deliberately and persistently altered (bucket count zeroed, synthetic descriptors).
   `acquire.cjs:77-80` refuses to retire unless the endpoint is fully consistent;
   `pipeline.cjs:126-129` will only `abandon()` (kill the runner, leave FS corrupted until
   reboot) if a failure happens after promotion or after `nativeRo` exists. **Console
   restart is the recovery**; FS does not self-heal. The `retire` path restores the owner
   and re-verifies (`retained/retained-memory.cjs:316-332`).
2. **Mid-wave interruption**: workers parked on the gate are unwound by patching their
   result slots to the exit gadget and signalling all gates, then joining with a 5 s bound
   (`probe-reserved-gap.cjs:1060-1074`). If the app process *dies* instead (a Civ7 crash),
   its kernel sessions auto-close, but FS may keep: the poisoned cache entry, the extra
   13616 bytes from pin/candidate storages, and a half-freed reservation group. A dead
   host mid-overwrite can also leave FS heap corruption ⇒ FS crash ⇒ system hang. The code
   treats any unexplained heap-counter drift as `placementUncertain` and *refuses further
   writes* (:459-470) — preserve evidence, reboot.
3. **Dirty cache entry**: while `cacheNeedsRestore` is set, the candidate storage holds a
   redirected cache entry. Normal restore = cmd 5 invalidate + prefix re-read
   (`probe-reserved-gap.cjs:663-682`); for the redirected *dirty* entry the restore is
   "clear the valid byte via one more field copy" — flushing/invalidating it directly is
   explicitly forbidden (:943-959). Interrupting between those steps leaves the alias live
   until reboot.
4. **Save-FS artifacts**: the scratch tree `/NS2_GAP_*` (16 MiB file + dirs) is deleted
   and committed on clean exit (:1082-1087); interrupted runs are cleaned on the *next*
   run by `cleanup-scratch.cjs:14-55` (deletes every root-level `NS2_GAP*` on `save` and
   `tmp`). RO donor files `/main` + `/main.npdm` are removed by `root-native-donor-cleanup`
   (`ro/files.cjs:47-78`); a stale pair from a crashed run is detected, hash-verified and
   removed by the next run's preflight (:102-149). **Corollary for Civ7: the exploit
   creates and deletes files at the root of the game's save FS — an interruption leaves
   foreign files in the player's save data, and a crash during the 16 MiB write could in
   principle corrupt the save. Recommend a throwaway profile/save.**
5. **RO process replacement**: the original `ro` is terminated and replaced by the payload
   (`ro/runtime.cjs:40-53`); README.md:60-61: restart the console when finished — that is
   also what restores the original RO. Until reboot, anything expecting stock `ro:dmnt`
   behavior talks to the payload.
6. **FS code patch**: the 16-byte `GetEventHandle` patch is always restored and read back
   before proceeding (`process/fs-execute.cjs:63-75`); an interruption with `pending` set
   leaves FS code modified until reboot.
7. **Held-RPC mode** (`hold.cjs`, pipeline `--hold-rpc`): keeps the app RPC and the FS
   endpoint alive; Ctrl-C or disconnect triggers retire; "a failed or interrupted cleanup
   may require a console restart" (README.md:89-94).

---

## Appendix A — Size/geometry constants the host must absorb

| Constant | Value | Where |
|---|---|---|
| Owned app allocation | 0x2400000 (36 MiB) | `probe-reserved-gap.cjs:26` |
| Per-wave save-file write | 0x1000000 (16 MiB) | `probe-reserved-gap.cjs:48` |
| Required save free space | 0x1410000 (~20.4 MiB) | `probe-reserved-gap.cjs:203` |
| Trigger path extent | 0x2441 bytes, 5 x 0x800 descriptors | `probe-reserved-gap.cjs:47,364-366` |
| Max IStorage receive per read | 0x200000 (2 MiB) | `probe-reserved-gap.cjs:19` |
| Min own-content storage | 0x1600000 (22 MiB) | `probe-reserved-gap.cjs:567,652` |
| Workers per wave | 13 | `probe-reserved-gap.cjs:299-301` |
| Reservation group | 59 objects x 208 bytes | `probe-reserved-gap.cjs:105,128` |
| Worker frame + snapshot | 0x40000 each | `probe-reserved-gap.cjs:397-398` |
| Retained heap capture | 0x4d8000 | `ro/install-retained.cjs:37` |
| FS domain capacity | 0x4000 entries | `ro/layout.cjs:25` |

## Appendix B — Engine process model the Civ7 host must replace

The PC engine drives everything; on-console, the SmileBASIC app supplied: the RPC loop,
the 0x80000 scratch, the 36 MiB allocation, 13+1 native worker threads, 4–5 light events,
counter/sleep primitives, and its `save` + `rom` mounts. CivSwitch already supplies the
RPC-equivalent primitives; everything else in this document is what must be re-established
*inside the Civ7 process* before `probe-reserved-gap.cjs` can run unmodified logic.
