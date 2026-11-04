# Civ7 nnSdk mount/proxy offsets

Scope: workstream B mount/runtime preparation for the exact SDK dumps in `dump/`. No hardware or network calls were made. All offsets below are module-relative to the SDK text base, not CivSwitch anchor-relative.

## Confirmed values

| Purpose | Offset | Static proof |
|---|---:|---|
| Mount-table list head | `0xB35870` | `0xAAF18/0xAAF1C` forms this address; `0xAAF10` passes it to the find implementation through `0x5E7FF0`. The dumped RW qwords at `+0/+8` are distinct, aligned 39-bit list links (`0x5F4886E3F8` and `0x5F4886E158` in the dump session). `0xA4420` walks `head+8`, compares each accessor name, and uses the adjacent lock at `head+0x10`. |
| Find wrapper, `verifiedFunctions[0]` | `0xAAF10` | Exact 20-byte match. Tail branch reaches the find thunk at `0x5E7FF0`; GOT `0xB272D0` contains SDK base + `0xA4420`. |
| Find implementation, `verifiedFunctions[1]` | `0xA4420` | Exact 176-byte match. Walks the intrusive list, compares names, and returns the accessor or the mount-not-found result. |
| Unmount implementation, `verifiedFunctions[2]` | `0xA4360` | Exact 192-byte match. Finds the named accessor, unlinks its node, releases it, and unlocks. Thunk `0x5E7FE0` resolves through GOT `0xB272C8`. |
| FileSystemAccessor open-file, `verifiedFunctions[3]` | `0xD3430` | Exact 236-byte match. Normalizes a path into a `0x300`-byte buffer and invokes implementation vtable slot `+0x60`, matching the reference helper's role. |
| `fsp-srv` proxy getter | `0xBD930` | Exact 152-byte match, including the reference ABI's output through `x8`. Its initializer at `0xBD9D0` references literal `"fsp-srv"` at `0x8E0F8A`; sibling initializers instead reference `"fsp-ldr"` and `"fsp-pr"`. |
| `fsp-srv` proxy global | `0xB4B450` | `0xBD950` loads the service pointer here; `0xBD93C` checks the flag at `0xB4B458`. This is beyond the dumped data and must be read at runtime. |
| Public `GetFreeSpaceSize` wrapper | `0xA75D0` | Exact 64-byte match. The function references literal `"GetFreeSpaceSize"` at `0x8D5B9D`; it is the public read-only `Result (*)(s64 *out, const char *path)` entry point. |
| `svcQueryMemory` wrapper | `0x168B0C` | Exact 32-byte match (`str x1,[sp,#-16]!; svc #6; ...; ret`). |

`port/sdk-layout.civ7.json` contains decimal mount offset **11753584** and the first four functions above in reference order. `port/civ7-app/sdk-proxy-code.json` contains decimal function offset **776496** and global offset **11842640**.

## Dump identity and verification

Run from the project root:

```
python port/tools/mount_verify.py
```

The verifier checks every emitted function byte string against the dump, decodes the mount-head and proxy references, checks the dumped list links and identifying strings, and prints source hashes. It completed successfully.

| Dump file | Module offset / actual size | SHA-256 |
|---|---|---|
| `4e102a4000.bin` | `0x0` / `0x602000` | `afaa7c04bffe9f269f5e87b7188da789ab5e59bc87a74acce10c1874432452c3` |
| `4e108a6000.bin` | `0x602000` / `0x4e7000` | `d254df72589ca862a8ab2767568b22cb48882fe44c7c9d30049258c5926fd97f` |
| `4e10d8d000.bin` | `0xAE9000` / `0x4B000` | `9aeed5286793786bec611fa198070350f9a0c56b61632d305a89cfa418b476fb` |
| `4e10dd8000.bin` | `0xB34000` / `0x10000` | `0eded832aae5b9c0c64e6b2e1c14bfa99c9e2bccd3f0efc5a3e0140820f9b092` |

The RW file is `0x10000` bytes on disk, although the older handoff says `0x8000`. The mount head at `0xB35870` is inside the actual dump. The proxy global at `0xB4B450` is not dumped.

## Rejected candidates

- `0xAED708` and `0xB22100` are vtable-related references in gamecard code, not the list head.
- `0xB4BAC0` belongs to allocator/initialization locking, not mount traversal.
- `0xB4B420` is reached from address-space/allocation code and is not the mount table.
- `0xB3F660` is a self-linked list in unrelated high-level code with no FS call path.

No value from these candidates is emitted.

## Runtime status

The probes completed successfully on hardware without save-FS writes or exploit acquisition:

- `save` and `rom` are mounted; a third mount is named `cache`.
- Save free space is `0x3EA8000`, passing the strict R11 threshold.
- A one-shot 36 MiB type-5 RW allocation succeeded and was freed. Multi-hour stability and FS quiescence remain unverified.
- The RomFS implementation/storage-wrapper/service vtable offsets are `0xAEDB68`, `0xAEAC28`, and `0xAEB9E8`.
- The session-manager layout matches `state[8] == 0x800` and `state[0x5C] == 3`; the RomFS storage chain and save service share the expected manager and expose a valid borrowed session.

These live values now populate `engine/shared/target.civ7.json`. The mount probe also captures raw manager state and borrowed handles so later boots can be checked rather than assumed identical.
