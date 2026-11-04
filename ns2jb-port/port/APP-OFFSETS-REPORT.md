# Workstream B-app — Civ7 app-layer offsets

## Scope and status

Derived from `dump/4e102a4000.bin` (Civ7 nnSdk .text, 0x602000 bytes) and the read-only data dumps. Offsets below are **module-relative**, not CivSwitch anchor-relative. No hardware or network access was used.

Emitted configs are in `port/civ7-app/`. They contain exact instruction bytes and semantic notes. `pthread_exit` is now confirmed by a defined ELF dynamic symbol. The native-worker configuration is **not yet drop-in ready** only because `call4` requires the documented table-slot adjustment. Timing and affinity also require consumer changes described below.

Dump SHA-256:

`afaa7c04bffe9f269f5e87b7188da789ab5e59bc87a74acce10c1874432452c3`

## Verification-prefix contract

`NativeClient.verifyFunction` accepts 4..256 instruction bytes. Every emitted `bytes` field is therefore the exact prefix `min(size, 256)` from the function offset, in a multiple of four. `size` remains the **full function-body size**, `prefixSize` records the emitted verification length, and `sha256` is computed over the **full body**, not truncated to the prefix. Unresolved entries retain null offsets and bytes.

The 256-byte cap applies to `pthread_create` (full size `0x220`), event `wait` (`0x160`), event `signal` (`0x118`), and `pthread_setaffinity_np` (`0x110`). The corrected `pthread_join` body is only `0xc8` and is emitted in full. Both validators enforce the cap, prefix/full-size relationship, full-body digest, and dump bytes.

## Native worker and frame gadgets

| Entry | Civ7 offset | Size | Semantic identification |
|---|---:|---:|---|
| `create` | `0x142180` | `0x220` | Defined dynamic symbol 21430, `pthread_create(thread*, attr, entry, arg)`. At `0x1421ac` a null attribute selects the default-attribute path at `0x142570`; the function allocates/initializes the thread, stores entry/argument, and returns the thread pointer. |
| `join` | `0x142480` | `0xc8` | Defined dynamic symbol 21128, `pthread_join(thread, result**, ...)`. Validates the thread, waits for its state transition, and returns the value stored at thread `+0x1d0`. |
| `exit` | `0x142410` | `0x70` | Defined dynamic symbol 9614, `pthread_exit`. Saves x0 as the thread result at `0x142478` before the non-returning exit path; safe as the final frame target. |
| `current` | `0x137050` | `0x0c` | Reads the current `nn::os::ThreadType*` from `TPIDRRO_EL0 + 0x1f8`. |
| `longjmp` | `0x5511b4` | `0x3c` | Restores x19–x30, SP, and d8–d15 from x0, normalizes w1 to 0/1, then `br x30`. Layout matches `shared/frames.cjs`. |
| `loadTable` | `0x4e094` | `0x18` | Exact reference gadget semantics: `x8=[x21]`, `x0=x8+(x20<<16)`, restores x20/x19/x21/x29/x30, `ret`. Frame x20 is zero, so x0 is the table self pointer. |
| `call4` | `0x359b88` | `0x38` | Moves x25/x21/x20/x19 to x0–x3, x30 to x7, loads x8 from `[x8,#0x70]`, `br x8`, then uses the reference epilogue. **Variant:** reference loads from `+0x68`. |
| `saveResult` | `0x28c980` | `0x10` | `str w0,[x1]`, restores x19/x29/x30, `ret`. |
| `saveResult64` | `0x19bcc0` | `0x10` | `str x0,[x1]`, restores x19/x29/x30, `ret`. |
| `tryWait` | `0x137110` | `0x14` | Public `nn::os::TryWaitThread` wrapper; forwards the thread pointer to the manager implementation. |
| `tryWaitImplementation` | `0x13e120` | `0xb8` | Defined dynamic symbol 9296, `ThreadManagerImplByHorizon::TryWaitForExitThread`. Polls with zero timeout; returns zero when exited and one when still running, matching worker join polling. |
| `sleep` | `0x137100` | `0x04` | Tail branch through the SDK sleep-thread import thunk. |

The ELF dynamic-symbol table was parsed with `port/tools/core_derive.py` through `port/tools/app_symbols.py` (23,046 symbols). This conclusively corrected the earlier control-flow-only candidates: the old `0x142410` join candidate was actually `pthread_exit`, join starts at `0x142480`, `0x13e31c` is `ResumeThreadUnsafe` rather than the try-wait implementation, and create has four additional trailing bytes (`0x220`, not `0x21c`). The validator now asserts these defined symbol offsets and sizes directly.

For exit, `0x14241c` moves x0 into x19, and `0x142478` is `str x19,[x8,#0x1d0]`. The following call enters the non-returning exit path after signaling the thread object at `+0x1d8`. Thus the existing final `saveResult64` → `pthread_exit` sequence preserves the last worker result for join without a frame-level exit adapter or extra register changes.

### Required frame-builder adjustment

The existing builder stores `call.function` at `table+0x78`. The table self pointer is `table+0x10`, so the reference `call4` finds it at self `+0x68`. Civ7's `call4` loads at self `+0x70`; store `call.function` at **`table+0x80`** instead. Each table allocation is 0x100 bytes, so this remains within the entry. All other selected gadget semantics and terminal instructions were checked.

### BTI / landing-pad check

A complete .text scan found no `BTI C`, `BTI JC`, `PACIBSP`, or `RETAB` opcodes. The selected `longjmp`, `loadTable`, `call4`, `saveResult`, and `saveResult64` entries begin without a BTI landing pad, as did the reference gadgets. `longjmp` terminates in `br x30`; the other gadgets end in `ret`.

This means there is no static evidence of a BTI/PAC-compliant alternative or of BTI being enforced for this nnSdk text. Runtime enforcement cannot be proven from the dump. The ordinary one-worker qualification must be the go/no-go check before creating wave workers; do not infer BTI safety solely from byte equality.

## Light events

All entries are in `event-code.json`.

| Entry | Civ7 offset | Size | Evidence |
|---|---:|---:|---|
| `initialize` | `0x1324e0` | `0x28` | Initializes the 8-byte event state, including manual-reset byte and signaled state. |
| `finalize` | `0x132510` | `0x08` | Clears the initialized byte and returns. |
| `wait` | `0x132680` | `0x160` | Atomic state loop with `svcWaitForAddress` at `0x1326d0`/`0x132794`. |
| `tryWait` | `0x1327e0` | `0x54` | Atomic signaled-state query with the same 0/1 result convention. |
| `signal` | `0x132520` | `0x118` | Atomic state transition with `svcSignalToAddress` at `0x13256c`/`0x1325c8`. |
| `clear` | `0x132640` | `0x38` | Atomically clears the signaled state. |
| `waitAddress` | `0x168d1c` | `0x08` | `svc #0x34; ret`. |
| `signalAddress` | `0x168d24` | `0x08` | `svc #0x35; ret`. |

## Timing and hashing

| Entry | Civ7 offset | Size | Evidence |
|---|---:|---:|---|
| `tick` | `0x137240` | `0x08` | `mrs x0,cntpct_el0; ret`. |
| `frequency` | `0x137270` | `0x0c` | Returns 19,200,000 Hz, the legacy SDK constant. |
| `priority` | `0x1370c0` | `0x08` | Loads the thread-priority halfword at `ThreadType+0x44`. |
| native frequency code | **RUNTIME-CONFIRMED** | — | Payload-side tick/sleep measurement (recon7.js) gives 31.25 MHz; the engine's measured mode verifies it with a 10 s window (RPC bracket noise ~2%). |
| `hash-code` | `0x4d40` | `0x6c` | Defined dynamic symbol 5867, `nn::crypto::GenerateSha256Hash`. Four-argument wrapper: initialize local context, update with `(input,count)`, get hash into `(output,outputBytes)`, finalize. |

The dynamic table distinguishes the adjacent wrappers: `0x4cd0` is `GenerateSha256`; `0x4d40` is the required `GenerateSha256Hash`. Their public semantics are equivalent, but the emitted entry now uses the exact named API and the validator asserts its defined symbol.

The old timing check's exact `45989888`-byte module-size discriminator must not be used for Civ7. Either verify the 31.25 MHz counter through a content-identified module after obtaining its dump, or replace that cross-check with a direct runtime tick/frequency consistency check. The 19.2 MHz legacy constant must not be substituted for the required 31.25 MHz hardware frequency.

## Thread scheduling and affinity

Confirmed entries in `thread-scheduling-reference.json`:

| Entry | Civ7 offset | Size |
|---|---:|---:|
| `pthread_getaffinity_np` | `0x1419e0` | `0xe4` |
| `pthread_setaffinity_np` | `0x141ad0` | `0x110` |
| `pthread_getschedparam` | `0x141be0` | `0xc8` |
| `pthread_setschedprio` | `0x141d80` | `0xb4` |
| `nn::os::SetThreadCoreMask` | `0x1371a0` | `0x1c` |
| `nn::os::GetThreadCoreMask` | `0x1371c0` | `0x1c` |
| `nn::os::GetCurrentCoreNumber()` | `0x137150` | `0x10` (`0x137160` is an equivalent alias) |
| `nn::os::GetThreadAvailableCoreMask()` | `0x1371e0` | `0x10` |
| detail `GetThreadAvailableCoreMask()` | `0x13e484` | `0x40` |
| detail `GetCurrentCoreNumber()` | `0x13e3e8` | `0x04` |

The detail available-mask implementation issues the expected core-mask `svcGetInfo` query and returns the unmasked process mask. The detail current-core implementation tail-branches to `svcGetCurrentProcessorNumber`.

### Replacement affinity config

`compat-affinity-reference.json` deliberately uses `mode: "direct-nnSdk"`.

- Available mask: call `nn::os::GetThreadAvailableCoreMask()` at `0x1371e0` directly.
- Worker get/pin: use `nn::os::GetThreadCoreMask` at `0x1371c0` and `nn::os::SetThreadCoreMask` at `0x1371a0`, with readback through the getter.
- Do **not** keep the old available-mask-only change while continuing to call `pthread_setaffinity_np`: at `0x141afc` that function calls the external compat import at `0x5e6c50`, then at `0x141b00` computes `requestedMask &= importedMask`. Direct `nn::os` get/set is required to bypass this restriction safely.

Confirmed pthread-compat evidence:

- GOT slot: `0xb26900`.
- Import stub: `0x5e6c50`, 16 bytes, exact-match validated.
- Captured session-absolute GOT target: `0x4e0291f970`. This is **not** a module-relative offset.

The external compatibility module was not dumped. Consequently its target offset, expected instruction bytes, and symbol string remain unresolved. They are only needed if the integration elects to retain pthread affinity instead of the direct replacement above; they do not block the direct design.

## Hardware qualification: create output anomaly (switch2-QnPKJX)

The app-only run reached worker creation with the byte-verified `pthread_create` at `0x142180`. It returned zero, but `native-worker.cjs` rejected the zero pointer in the output slot; cleanup was deferred with `qualify-1793639025723:creating` still tracked and `cleanedUp:false`. `slot+8` is only the later join-result buffer, so its zero value has no diagnostic significance before join.

Static analysis gives a concrete explanation for the zero output:

1. The public argument ABI matches SmileBASIC: Civ7 saves the output slot in x19, entry in x22, and entry argument in x21; null attributes select the default path at `0x142570`. The default is joinable, with stack size `0x14000`, priority 20, and no caller-supplied stack. Attribute validation/allocation failures return nonzero (`0x16`, `0xb`, or `0xc`), not the observed zero.
2. Civ7 allocates the thread object in x23 and forms the actual internal pointer `x20=x23+0x310` at `0x142340`.
3. At `0x14234c`, `x8=x21+(w0<<3)`, where x21 is the entry argument (`ownedFrameBase`). At `0x142354`, it stores x20 at `[x8+0x80]`. Thus the actual internal thread pointer is written at `ownedFrameBase+(helper_w0<<3)+0x80`.
4. At `0x14235c`, `ands x8,x23,#7` computes only the low three bits of the aligned thread object. At `0x142364`, `str x8,[x19]` writes that value to the caller's output slot. An 8-byte-aligned object therefore produces output zero despite the successful return at `0x142370`.
5. SmileBASIC also uses the same four-argument public ABI and null-default path, but its tail at create `+0x234` stores the actual internal thread pointer to the output slot. This is the material output-semantics difference; changing the create offset or default attributes is not justified.

The create config now records these corrected output semantics. The actual pointer value has **not** been confirmed at runtime, so no blind pointer substitution is approved. `w0` is the helper return at `0x142348` and is not saved in the frame; its value is not statically known.

Use this bounded, read-only diagnostic on the already-created worker, before rejecting or joining it:

1. Read only the four candidate qwords at `ownedFrameBase+0x80`, `+0x88`, `+0x90`, and `+0x98`, corresponding to `w0=0..3`. This is a deliberate diagnostic bound, **not** a claimed semantic maximum for w0. Do not read beyond owned memory or infer w0 from unrelated frame contents.
2. For each nonzero, 8-byte-aligned candidate, use `svcQueryMemory` to validate the covering mapping before dereferencing it.
3. `0x1422f8` stores the entry and argument at thread object `+0x1c0/+0x1c8`. Since the candidate is object `+0x310`, verify `[candidate-0x150] == sdk+0x5511b4` and `[candidate-0x148] == ownedFrameBase`. This validates the already-created worker using reads only; do not call through an unvalidated pointer.
4. If exactly one candidate matches, that is the supported location from which the engine can obtain the worker handle instead of the output slot. If none matches, stop and instrument the helper result at `0x142348`; do not widen the search or guess. Do not proceed to FS waves with the deferred creating thread, and do not change create/default attributes.

Reproduction: `python port/tools/app_create_analysis.py` checks the exact instructions, decodes `x23&7` without any conflicting mask description, compares the SmileBASIC prologue/tail, resolves relevant thunks, and prints these run-specific candidate addresses and expected entry/argument values.

## Direct `nn::os` thread alternative

`thread-code.json:directNnOs` now records **NO_GO_CREATE_THREAD_HANG_UNRESOLVED**. Two independent clean processes hung inside CreateThread with the statically correct object/stack inputs, and StartThread was never reached. The previous direct-path recommendation is withdrawn; no further attempts are justified without evidence locating the blocking call. The old pthread output formula should not be pursued either: helper `0x143110` returned `0x19`, and a guarded full-frame scan found no matching pthread object.

| Entry | Offset / size | Exact verification bytes |
|---|---|---|
| default-core `nn::os::CreateThread` | `0x136d50` / `0x28` | `684f0090e603052a084141f9e50304aae40303aae30302aae20301aae10300aa00c103915fd01214` |
| `nn::os::StartThread` | `0x136da0` / `0x14` | `684f0090e10300aa084141f900c1039158d01214` |
| `nn::os::DestroyThread` | `0x136d80` / `0x14` | `684f0090e10300aa084141f900c103915cd01214` |
| direct exit continuation | `0x13e094` / `0x20` | `284f0090083d40f9080140f9480000b400013fd6a9aa00941f2003d500000014` |

Exact call and object semantics:

- `CreateThread(thread, entry, argument, stack, stackBytes, priority)` takes x0=`ThreadType*`, x1=entry, x2=argument, x3=stack, x4=stack size, w5=priority. The default-core manager overload at `0x13819c` sets w7=`-2`. Use entry `sdk+0x5511b4`, argument `ownedFrameBase`, a separate page-aligned `0x14000`-byte RW stack, and priority 20 (stored at `ThreadType+0x88`).
- A zeroed **0x400-byte `ThreadType` buffer is too small**. `ThreadManager::CreateThread` clears 0x1c0 bytes and writes through `+0x1b4`, but also writes a flag at `+0x600` (`0x137f34`). Minimum addressed extent is `0x601`; use a zeroed, page-aligned **0x1000-byte** owned buffer. Keep the stack separate.
- `StartThread(thread)` and `DestroyThread(thread)` take the direct `ThreadType*` in x0 and return a result code. Require zero from create/start/destroy.
- Existing `TryWaitThread` at `0x137110` and `TryWaitForExitThread` at `0x13e120` are compatible. Result **1 means exited**, 0 means still running: the implementation initializes w20=1 and returns it after a successful synchronization wait; timeout `0xea01` returns zero.
- Direct Get/SetThreadCoreMask at `0x1371c0`/`0x1371a0` is compatible with this object: both accept `ThreadType*`, and the detail implementations use the kernel handle at `+0x1b0`. Use the direct available-core mask and getter readback; no pthread affinity or compat mask is involved.

`pthread_exit` at `0x142410` is **not compatible** with direct threads. It reads a musl thread object from `TPIDRRO_EL0+0x1e0` and stores x0 at that object's `+0x1d0`; direct CreateThread initializes the nn::os slot at `TPIDRRO_EL0+0x1f8` (`0x13e04c`) but does not create the musl object. Therefore direct `ThreadType+0x1d0` is not a supported result field.

The normal direct-thread return continuation would be `0x13e094`, immediately after the bootstrap's `blr` at `0x13e090`, followed by the optional exit hook and `svcExitThread`. This remains valid static metadata but is **not a workaround** for a create that never returns. A plain `ret` gadget would loop on crafted x30, and `pthread_join` is not part of the direct lifecycle.

Create-hang analysis and go/no-go:

- `ThreadManager::CreateThread` itself clears 0x1c0 and initializes the object, so no magic/pre-initialization beyond valid storage is missing. It stores stack address/size at `+0x48/+0x50`, argument at `+0x60`, and entry at `+0x68`.
- Impl `0x13dcc4` computes `stack_top = [thread+0x50] + [thread+0x58]` and stores the entry at top-0x20. Thus a page-aligned base plus `0x14000` is the expected form; it does not execute or validate longjmp/frame before returning.
- The only explicit resource retry is bounded: ten `svcCreateThread` attempts with ten `0x989680`-ns sleeps, followed by result `0x1203`. That cannot explain an indefinite hang. Other possible blocking sites are the manager's lock/list registration or the kernel create call itself, but static code cannot identify which blocked on hardware.
- Most importantly, pthread_create does **not** use a different creator: its call at `0x1422d0` resolves through `0x5e6b30` to the same exported `0x136d50`, and its start path resolves through `0x5e6b40` to `0x136da0`. Therefore there is no evidence that direct CreateThread requires a special SDK thread context, and no input-only explanation for why the same function would hang only with these arguments.
- **Decision: NO-GO.** No concrete correction is established. Do not retry direct CreateThread, StartThread, exitContinuation, or DestroyThread as workarounds. A future diagnosis would need the exact blocking PC/lock/SVC from runtime evidence; guessing from the static list is not sufficient.

Reproduction: `python port/tools/app_direct_analysis.py` resolves the identical pthread callees and checks object clearing, stack-top formation, and the bounded retry loop.

## Recovering the existing pthread worker through the manager list

`thread-code.json:managerListRecovery` records a **statically supported, bounded list walk**. This does not retry direct CreateThread or the old frame-output formula. It targets a worker that pthread_create may already have inserted and started before returning its anomalous zero output.

Static layout evidence:

- All public wrappers load a pointer at `sdk+0xb22280` and add `0xf0`; therefore `manager = read64(sdk+0xb22280) + 0xf0`.
- Constructor `0x138604` initializes `manager+0x1d0` to that same address, establishing the empty-list sentinel. `manager+0x1c8` is the associated manager lock.
- Create inserts the new node at the head before StartThread (`0x13804c..0x13806c`). Nodes have next at `+0x0` and previous at `+0x8`; entry is at `+0x68` and argument at `+0x60`. DestroyThreadObject at `0x138340` unlinks a node.
- pthread_create places this inner `ThreadType` at `pthread_base+0x310`. It also stores entry/argument at `pthread_base+0x1c0/+0x1c8`. Thus a manager node identifies both the direct object and its enclosing pthread object without relying on the output slot.

Bounded guarded-read diagnostic:

1. Validate a readable mapping for `manager` through `manager+0x1e8`. Set `sentinel=manager+0x1d0` and `node=read64(sentinel)`.
2. Keep a visited-address set. Traverse at most **128 nodes**: stop at `sentinel`; reject an unaligned node, duplicate/self-cycle, or a mapping that does not cover `node` through `node+0x608`. Read next only as `read64(node+0)`.
3. A candidate matches only if `read64(node+0x68) == sdk+0x5511b4` and `read64(node+0x60) == ownedFrameBase`. For the archived example, frame base is `0x597cd0f000`; ASLR makes this value run-specific, so use the actual base for any new run.
4. Set `pthreadBase=node-0x310`, validate its mapping through `+0x1c8`, and require `read64(pthreadBase+0x1c0)==sdk+0x5511b4` and `read64(pthreadBase+0x1c8)==ownedFrameBase`. If no node matches within the cap or any guard fails, stop without native operations.
5. Revalidate the node and linkage immediately before operations. Use `0x1371c0(outIdealCore,outMask,node)` for GetThreadCoreMask and `0x1371a0(node,0,mask)` followed by getter readback for SetThreadCoreMask. These use the direct kernel handle at `node+0x1b0`.
6. Poll `0x137110(node)`: 0 means still running, 1 means exited. Do not destroy a gate-blocked running worker. Only after result 1, call `0x136d80(node)` and require zero. No pthread_join or new CreateThread is needed.

The separate pthread bookkeeping structures are not needed for this walk; the manager's own list is the authoritative path to the inner object and avoids relying on undocumented global pthread-list state.

Reproduction: `python port/tools/app_thread_list.py` asserts the constructor, insertion, and object-field instructions and prints the guarded offsets.

**Runtime outcome: NO-GO.** In `switch2-HqnE06`, the result sentinel remained unchanged after `pthread_create`, confirming that the worker had not run through its gate. The guarded walk then traversed 19 nodes and found no matching entry/argument. Thus pthread returned success without creating a list-visible worker. The static list layout is valid, but it cannot recover a nonexistent object. `target.civ7.json` now blocks preflight with `no-go-worker-creation`; do not repeat direct CreateThread, the output-formula probe, or manager-list recovery without new runtime evidence.

## Raw svcCreateThread bypass — new runtime experiment (hardware-pending)

The create-hang analysis above narrowed the block to either the nn::os manager lock/list
registration or the kernel `svcCreateThread` itself. A full scan of the nnSdk text dump
(`dump/4e102a4000.bin`) located the bare syscall wrappers, all byte-verified offline by
`python port/tools/raw_svc_probe_validate.py`:

| Function | SDK offset | Bytes | ABI |
|---|---|---|---|
| ~~`svcExitProcess`~~ | `+0x168B24` | `e10000d4c0035fd6` | svc #0x07 — **DO NOT USE: kills the whole game process** |
| `svcExitThread` | `+0x168B4C` | `410100d4c0035fd6` | svc #0x0A; no args, never returns |
| `svcCreateThread` wrapper | `+0x168B2C` | `e00f1ff8010100d4e20340f9410000b9ff430091c0035fd6` | x0=&out handle, x1=entry, x2=arg, x3=stack_top, w4=priority, w5=core; w0=result, handle stored to [x0] |
| `svcStartThread` | `+0x168B44` | `210100d4c0035fd6` | svc #0x09; w0=handle -> w0=result |
| `svcSleepThread` | `+0x168B54` | `610100d4c0035fd6` | svc #0x0b; x0=ns |
| `svcGetThreadPriority` wrapper | `+0x168B5C` | `e00f1ff8810100d4e20340f9410000b9ff430091c0035fd6` | x0=&out prio, w1=handle |
| `svcGetThreadCoreMask` wrapper | `+0x168B7C` | `e007bfa9c10100d4e30340f9610000b9e30740f9620000f9ff430091c0035fd6` | x0=&out core, x1=&out mask, w2=handle |
| `svcSetThreadCoreMask` | `+0x168B9C` | svc #0x0f | w0=handle, w1=core, x2=mask; affinity without a ThreadType |
| `svcGetCurrentProcessorNumber` | `+0x168BA4` | `010200d4c0035fd6` | svc #0x10; current core in w0 |
| `svcCloseHandle` | `+0x168BE4` | `c10200d4c0035fd6` | svc #0x16; w0=handle |
| `svcWaitSynchronization` wrapper | `+0x168BF4` | `e00f1ff8010300d4e20340f9410000b9ff430091c0035fd6` | x0=&out index, x1=handles, w2=count, x3=timeout ns; w0=result, index stored to [x0] |
| `svcWaitProcessWideKeyAtomic` | `+0x168C24` | svc #0x1c | TLS-free gate wait for worker frames |
| `svcSignalProcessWideKey` | `+0x168C2C` | svc #0x1d | gate release |

**Runtime results (hardware, this session):**

- Raw `svcCreateThread` **returns synchronously — it does not hang.** The direct
  `nn::os::CreateThread` hang is therefore in nn::os bookkeeping (manager lock/list
  registration), not the kernel SVC. The bypass hypothesis is confirmed viable.
- Core parameter: `-2` (default) and cores 0-5 are rejected with `0xE001` (InvalidCoreId);
  cores 6 and 7 pass core validation, so the process core mask is most likely 0xC0.
  `svcGetCurrentProcessorNumber` reported 0 for the JS thread — do not rely on it for the
  allowed mask.
- Priority 20 is rejected with `0xE201` (InvalidPriority). Priority-mask queries via
  pseudo-handles (`0xFFFF8000`/`0xFFFF8001`) fail with `0xE401` on `svcGetInfo` (ids 0/1),
  `svcGetThreadPriority`, and `svcGetThreadCoreMask` — this kernel appears to reject
  pseudo-handles for these calls; a **real** thread/process handle is required.
- Next step (in progress when the session ended): borrow scheduling parameters from an
  existing game thread via the nn::os manager list (`sdk+0xB22280`, manager `+0xF0`, sentinel
  `+0x1D0`, node handle `+0x1B0`, priority halfword believed at `+0x88` but read back 0 —
  field offset needs re-verification against a dumped node), then `svcGetThreadCoreMask` with
  the real handle, and retry phase A with the borrowed priority/core.
- **RESOLVED (2026-11-02, home session):** recon6 dumped the first 8 manager-list nodes and
  queried the kernel through each node's real handle at `+0x1B0`. `svcGetThreadPriority`
  (wrapper `+0x168B5C`, bytes verified) succeeds on real handles — observed priorities 43,
  43, 43, 43, 44, 59, 28, 28 — as does `svcGetThreadCoreMask` (masks 0x4/0x2/0x20/0x10,
  ideal cores 1/2/4/5). The struct halfword at `+0x88` is confirmed NOT the priority; no u16
  in the node's first 0x100 bytes mirrors the kernel value either, so the probe takes the
  kernel value as authoritative instead of any struct field. `probe_raw_svc_thread.js` now
  borrows the priority via `svcGetThreadPriority` on the first node's handle and tries cores
  6 and 7 after the borrowed-mask cores (earlier runs showed cores 0-5 rejected with
  `0xE001` even before priority validation mattered, while 6/7 passed core validation).
  The probe's `svcQueryMemory`-derived base needs no subtraction (`sdk = read64(aux)`);
  the earlier garbage `manager=` print came from subtracting `0x168B0C`.
- Phase B's frame exit target is the `+0x168B4C` ExitThread gadget (the pthread `exit`
  continuation reads TPIDRRO_EL0 and cannot terminate a raw thread).

Calling `+0x168B2C` directly skips all nn::os bookkeeping (ThreadType, manager lock, list
registration). If the raw call succeeds, the hang was in nn::os bookkeeping and raw threads
running longjmp frames built only from bare svc gadgets become the worker mechanism. If the raw
call hangs or returns a kernel error, the block is kernel-side and this route is definitively
dead. The experiment is `port/probes/probe_raw_svc_thread.js`:

- Phase A: one thread whose jmp_buf (`x30`=`+0x168B24`, valid SP) exits immediately; success =
  `svcWaitSynchronization` on the handle returns 0. Exactly one create attempt, priority 20,
  core -2, with a `create-attempt` log line immediately before the call so a hang is identifiable.
- Phase B (only if A passes): one full one-call worker frame (longjmp -> loadTable -> call4 ->
  memmove -> saveResult64 -> svcExitThread) in the exact `shared/frames.cjs` layout, verifying
  the sentinel write, stored result, and clean exit.

Raw threads have
no nn::os ThreadType, so affinity uses `svcSetThreadCoreMask` (wrapper `+0x168B9C`, kernel ABI
`w0=handle, w1=ideal, x2=mask`) with the kernel handle instead of
`nn::os::SetThreadCoreMask`. **Status: QUALIFIED — phases A+B passed on hardware
(2026-11-02), the `raw-svc` engine mode is implemented, and `run.cjs --app-only` passes with
a raw worker (create/start/pin/frame/join/close all verified).** The
`no-go-worker-creation` gate in `target.civ7.json` is lifted; `target.thread.mode` is now
`raw-svc`. Raw threads receive a usable nonzero TPIDRRO_EL0 from the kernel
(`0x1d67f89200` measured via the `readTpidrro` gadget at `+0x14BA80`), so the Stage-4 IPC
path is viable.

## Unresolved items and blockers

1. **`timing-code.json:nativeFrequencyCode`** — No native/compat module dump exists, so exact bytes and a module-relative offset cannot be derived. The old region-size heuristic is target-specific and rejected. A direct runtime tick/frequency consistency check is the alternative.
2. **`compat-affinity-reference.json:pthreadAffinityCompatibility.target`** — External target bytes and symbol are unavailable. Use the direct `nn::os` design instead, or dump/identify that module before retaining pthread affinity.

`pthread_exit` is no longer unresolved; its defined symbol and exact result-store semantics are documented above. No offset was populated for either remaining unresolved item; each has explicit null `offset`/`bytes` fields and a blocker string.

## Validation

Reproduction and validation commands, run from the workspace root:

```
python port/tools/app_build.py
python port/tools/app_validate.py
python port/validate_offsets.py port/civ7-app/*.json
```

Final result:

- All six B-app JSON files parsed successfully.
- **40 resolved byte signatures** matched `dump/4e102a4000.bin` exactly. Every verification prefix is within 4..256 bytes; full-body sizes and SHA-256 digests were independently checked.
- Defined dynamic symbols passed for create/join/exit/try-wait/`GenerateSha256Hash` and the direct nn::os create/start/destroy functions; the `pthread_exit` store instruction at `0x142478` was checked explicitly.
- Direct nn::os checks passed for the 0x1000-byte object requirement, separate stack, exit continuation, destroy-based cleanup, and direct affinity.
- Gadget boundary checks passed: `loadTable` size `0x18`, `call4` size `0x38`, terminal `ret` for `call4`/`loadTable`/`saveResult`/`saveResult64`, and terminal `br x30` for `longjmp`.
- The compat GOT captured target was re-read from `dump/4e10d8d000.bin` and matched `0x4e0291f970`.
- Exactly two documented unresolved entries remained: native frequency code and external pthread-compat target.
- `cache-mount-sdk.json` and `sdk-proxy-code.json` were not edited by B-app.
- BTI/PAC opcode scan passed as described above.

No runtime call, hardware thread creation, counter read, hash test, or affinity readback was performed; those remain hardware qualification steps.

Analysis tooling uses the required naming convention: `port/tools/app_semantic.py`, `app_a64.py`, `app_build.py`, `app_validate.py`, and `app_symbols.py`. `app_symbols.py` reuses `core_derive.py`'s ELF dynamic-table parser. The default Python installation lacked Capstone, so `app_semantic.py` uses the local read-only `app_a64.py` decoder for common AArch64 instructions when Capstone is unavailable. Emitted bytes always come directly from the binary dump, not from the decoder.
