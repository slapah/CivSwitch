# Civ7 offset and integration report

## Status

The static Civ7 SDK port is complete for the supplied dumps. **60 emitted function signatures** match `dump/4e102a4000.bin` exactly, with offsets relative to the SDK text base. Every signature is 4–256 bytes and satisfies `NativeClient.verifyFunction`.

Detailed derivation evidence is in:

- `CORE-OFFSETS-REPORT.md` — core functions, ELF symbols, relocations, SVCs, and CRC.
- `APP-OFFSETS-REPORT.md` — workers, events, timing, hashing, affinity, and full-body metadata.
- `MOUNT-OFFSETS-REPORT.md` — mount table, proxy, free-space helper, and dump identity.
- `RESIDUAL-OFFSETS-REPORT.md` — cache-mount helpers, residual SVCs, FS geometry, and title IDs.

No network or hardware result is implied by these static checks.

## Artifacts

- `sdk-functions.civ7.json`: 12 validated core entries.
- `sdk-layout.civ7.json`: mount head `0xB35870` plus 4 validated mount functions.
- `civ7-app/*.json`: 44 validated app/proxy/cache-mount entries.
- `engine/shared/target.civ7.json`: target configuration and explicit runtime gates.
- `engine/`: config-driven PC engine; the supplied `ns2jb-main/` tree was not edited.

Key offsets:

| Function/object | Civ7 module offset |
|---|---:|
| `memcpy` / `memmove` / `memset` | `0x5224E0` / `0x522830` / `0x522AF0` |
| `svcQueryMemory` | `0x168B0C` |
| `svcSendSyncRequest` / `svcCloseHandle` | `0x168C54` / `0x168BE4` |
| `nnutilZlib_crc32` | `0x72F50` |
| `allocate` (`posix_memalign`) / `free` PLT | `0x512F40` / `0x5E4C90` |
| `nn::sm::GetServiceHandle` | `0x14CC90` |
| `pthread_create` / `pthread_join` / `pthread_exit` | `0x142180` / `0x142480` / `0x142410` |
| `longjmp` / `loadTable` / `call4` | `0x5511B4` / `0x4E094` / `0x359B88` |
| Light-event init/wait/signal/clear | `0x1324E0` / `0x132680` / `0x132520` / `0x132640` |
| Counter tick / legacy frequency | `0x137240` / `0x137270` |
| SHA-256 wrapper | `0x4D40` |
| Direct nn::os set/get core mask | `0x1371A0` / `0x1371C0` |
| Mount table / fsp-srv proxy getter | `0xB35870` / `0xBD930` |
| fsp-srv proxy global / `GetFreeSpaceSize` | `0xB4B450` / `0xA75D0` |

The SDK text size is `0x602000`; its zlib CRC-32 is `157086863` (`0x095CF48F`). The bridge resolves memmove from the live SDK base and sends this CRC in HELLO. The engine independently calls the verified CRC wrapper over live memory during qualification.

## Required consumer changes

- Worker `call4` loads its target from self `+0x70`, so the frame builder stores it at `table+0x80`. The original `table+0x78` layout remains the default for SmileBASIC.
- Civ7 has a direct nn::os worker lifecycle: 0x1000-byte objects, separate 0x14000-byte stacks, six-argument `CreateThread` at `0x136D50`, `StartThread`, `DestroyThread`, and exit continuation `0x13E094`. A continuation record carries arguments five and six through the console's verified `call_rop` path.
- Civ7 uses direct `nn::os::GetThreadCoreMask`/`SetThreadCoreMask`, not pthread affinity through the external compatibility mask.
- The SDK frequency function returns the legacy 19.2 MHz constant. Civ7 verifies that value, then measures the actual counter over a one-second console sleep with a 10% tolerance. Race calculations use the exact 31.25 MHz hardware constant.
- Civ7 does not use SmileBASIC's HELLO GOT/backing/controller fields or activity-report keep-awake chain. CRC, mapping, instruction, memory, and cleanup checks remain enforced.
- The residual SVC wrappers and FS-process geometry are configured in `target.civ7.json`. The RO donor remains system title `0x0400000000000037`, matching the existing payload manifest.

The two remaining static nulls are intentionally not used by those replacements: the external compatibility frequency function and external pthread compatibility target. Direct measured timing and direct nn::os affinity avoid them.

## Hardware bring-up status

The bridge passed on hardware: HELLO, `svcQueryMemory`, `memset`, `memcpy`, read-back integrity, and clean shutdown all succeeded. The runtime probes then established:

| Check | Result |
|---|---|
| R10/R12 mounts | `save` and `rom` are present; 3 mounts total (`save`, `rom`, `cache`) |
| R11 save space | `0x3EA8000` bytes free, strictly above `0x1410000` |
| R2 allocation | One 36 MiB contiguous, page-aligned type-5 RW allocation succeeded and was freed |
| RomFS implementation vtable | `0xAEDB68` |
| RomFS storage-wrapper vtable | `0xAEAC28` |
| RomFS service vtable | `0xAEB9E8` |
| Session manager | Size `0x800`, state offset `0x5C`, value `3`; borrowed session and shared storage/save manager verified |

The host title is configured as `0100C3601518C000`, corroborated by this [Eden issue report](https://github.com/eden-emulator/Issue-Reports/issues/213) and this [GBAtemp cheat/title listing](https://gbatemp.net/threads/cheat-codes-ams-and-sx-os-add-and-request.520293/page-3512). The engine's live identity check has not yet been reached, so this remains subject to final runtime verification.

App-only qualification passed bootstrap CRC/memory checks, memory mapping, mount inspection, measured counter frequency, native SHA-256, and multipart transfer. No safe worker path works on this build: direct `nn::os::CreateThread` hangs before `StartThread`, while `pthread_create` returns success without inserting a worker. The result sentinel remains unchanged and a bounded manager-list walk finds no match. Six-argument `call_rop` passed independently with memcpy/read-back. Further create attempts are blocked at preflight; no FS cleanup or acquisition stage was entered. Multi-hour allocation stability and FS quiescence also remain unverified.

`probes/` contains bounded, non-acquisition payloads for mount inspection, save free space, and allocation feasibility. `engine/run.cjs --app-only` stops before save cleanup and FS acquisition.

## Verification

From the project root:

```sh
python port/tools/core_derive.py
python port/tools/app_validate.py
python port/tools/mount_verify.py
python port/tools/mount_probe_validate.py
python port/tools/residual_validate.py
python port/validate_offsets.py port/sdk-functions.civ7.json port/sdk-layout.civ7.json port/civ7-app/*.json
```

From `port/` with Node 22+:

```sh
node --test engine/target.test.cjs engine/test.cjs engine/switch2/retained/*.test.cjs engine/switch2/ro/layout.test.cjs engine/switch2/memory/wave-overlap.test.cjs test_civ_bridge.cjs
```

Current results: **41/41 tests passed**, 94 JavaScript files passed syntax checks, and all 60 emitted signatures matched. Hardware execution remains a separate staged bring-up.
