# Civ7 B-core SDK offsets

## Scope and result

Statically derived from `dump/4e102a4000.bin` (module text offset 0, size `0x602000`), with symbol and relocation evidence from `dump/4e108a6000.bin` and `dump/4e10d8d000.bin`. No network or hardware calls were made.

`port/sdk-functions.civ7.json` uses the reference `name -> {offset, bytes}` schema. Offsets are relative to the SDK module text base, not the CivSwitch `sdk_base` anchor. Every `bytes` value is the exact little-endian instruction sequence at its emitted offset and satisfies `verifyFunction`'s 4-byte alignment and 4..256-byte signature limits.

All requested minimum symbols and the native CRC-32 wrapper are resolved. The JSON also retains the reference engine's `send` and `close` keys alongside the descriptive aliases `svcSendSyncRequest` and `svcCloseHandle`.

## Emitted offsets

| JSON key | Module offset | Verified signature length | Derivation | Confidence |
|---|---:|---:|---|---|
| `allocate` | `0x512F40` | 64 bytes | Defined `posix_memalign` dynamic symbol, size `0xC8`; three-argument/out-pointer behavior matches `Session.allocate` | High |
| `free` | `0x5E4C90` | 16 bytes | Unique PLT thunk for the GOT relocation naming the undefined `free` import | High for thunk identity; external implementation not dumped |
| `getService` | `0x14CC90` | 64 bytes | Defined `_ZN2nn2sm16GetServiceHandleEPNS_3svc6HandleEPKcm`, size `0x170`; also an exact match to the reference function's first 52 bytes | High |
| `send` | `0x168C54` | 8 bytes | Unique `svc #0x22; ret` (`SendSyncRequest`) | High |
| `svcSendSyncRequest` | `0x168C54` | 8 bytes | Alias of `send` | High |
| `close` | `0x168BE4` | 8 bytes | Unique `svc #0x16; ret` (`CloseHandle`) | High |
| `svcCloseHandle` | `0x168BE4` | 8 bytes | Alias of `close` | High |
| `memset` | `0x522AF0` | 64 bytes | Defined `memset` dynamic symbol, size `0xCC` | High |
| `memcpy` | `0x5224E0` | 64 bytes | Defined `memcpy` dynamic symbol, size `0x2C0` | High |
| `memmove` | `0x522830` | 64 bytes | Defined `memmove` dynamic symbol, size `0x164`; also the weak `__memmove_device` alias | High |
| `svcQueryMemory` | `0x168B0C` | 24 bytes | Unique `svc #6` at `0x168B10`, including its stack prologue/epilogue; agrees with the previously hardware-verified offset | High |
| `crc32` | `0x72F50` | 8 bytes | Defined `nnutilZlib_crc32` dynamic symbol; three-argument branch wrapper matching the engine's checksum call | High |

The nearby `0x5227A0` routine is `__memcpy_fast`, not the canonical `memcpy` export. It is deliberately not used for the `memcpy` key.

## Symbol and relocation evidence

The ELF dynamic table starts at module `0xB21980`. Its relevant relative-address entries are:

- `DT_RELA = 0x6452E0`, `DT_PLTRELSZ = 0x2CFE8`
- `DT_SYMTAB = 0x6CC488`, `DT_SYMENT = 0x18`
- `DT_STRTAB = 0x753518`, `DT_STRSZ = 0x16DD30`

The table directly names `posix_memalign`, `memcpy`, `memmove`, `memset`, and `nn::sm::GetServiceHandle` at the offsets above. This is stronger evidence than prologue similarity or masked byte matching.

For `free`, dynamic symbol index 2 is the undefined `free` import. Its sole `R_AARCH64_JUMP_SLOT` (`0x402`) relocation targets module GOT slot `0xB25920`. A complete PLT scan finds exactly one thunk loading that slot, at `0x5E4C90`:

```text
adrp x16, ...
ldr  x17, [x16, ...]
add  x16, x16, ...
br   x17
```

The emitted signature verifies those PLT instructions. Calling this thunk requires the normal runtime relocation at `0xB25920`; no claim is made about the external implementation address.

The SVC scan finds exactly one site for each required SVC number. `svcQueryMemory` starts four bytes before its SVC with bytes `e10f1ff8` (`str x1, [sp, #-0x10]!`). The older `port/tools/locate.py` pattern used `e11f0ff8`, which explains its false `MISSING` result; the emitted JSON uses the actual dump bytes.

## Core native/bridge constants

- SDK executable text size: `0x602000` bytes. This supersedes SmileBASIC's `0x5E1000` for Civ7 bounds checks.
- Standard CRC-32/zlib CRC of exactly those text bytes: decimal `157086863`, hexadecimal `0x095CF48F`. This is statically computed, not checked through the console's CRC function.
- Diagnostic only: the `free` import's GOT slot is module `0xB25920`. It is not a HELLO `got` value and must not be substituted for SmileBASIC's main-module GOT constant.

## Validation

Reproduce derivation and byte validation with:

```bash
python port/tools/core_derive.py
```

Regenerate the JSON and validate it again with:

```bash
python port/tools/core_derive.py --write
```

The tool uses only the Python standard library. It independently re-reads the dynamic symbols, relocations, PLT target, and SVC sites; checks the required key set and aliases; rejects stale output by comparing a fresh derivation; and verifies that every emitted signature lies wholly inside the text dump and exactly matches the dump bytes.

The generation run passed all 12 entries:

```text
allocate             0x512F40  64 bytes  OK
free                 0x5E4C90  16 bytes  OK
getService           0x14CC90  64 bytes  OK
send                 0x168C54   8 bytes  OK
close                0x168BE4   8 bytes  OK
memset               0x522AF0  64 bytes  OK
memcpy               0x5224E0  64 bytes  OK
memmove              0x522830  64 bytes  OK
svcQueryMemory       0x168B0C  24 bytes  OK
svcSendSyncRequest   0x168C54   8 bytes  OK
svcCloseHandle       0x168BE4   8 bytes  OK
crc32                0x072F50   8 bytes  OK
text size: 0x602000
text CRC-32: 157086863 (0x095CF48F)
free GOT: 0xB25920
```

## Remaining uncertainties and excluded symbols

- The implementation reached by the `free` PLT thunk is outside the supplied SDK dumps. Its thunk and relocation are resolved; its final runtime target is **unresolved statically**. No external target address is guessed.
- HELLO `got`, `backing`, and `controller` are deliberately zero because the Civ7 engine target does not use those SmileBASIC fields. `memmove` and the text CRC are configured, but pairing/runtime validation was outside this static task.
- Reference-schema socket helpers (`socket`, `connect`, `closeSocket`, `fcntl`, `poll`, `errno`) were not required for B-core and are intentionally omitted rather than populated from weak pattern matches.
- Mount-table/layout values, thread/event/timing/hash/proxy functions, and app-specific JSON remain outside this report. No `sdk-layout`, mount, engine, app-specific JSON, or `ns2jb-main` files were changed.
- Runtime behavior, relocations, allocator success, IPC behavior, and `verifyFunction` on hardware remain untested by design.
