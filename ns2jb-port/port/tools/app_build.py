#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
from app_a64 import disassemble

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "port/civ7-app"
TEXT = (ROOT / "dump/4e102a4000.bin").read_bytes()
BASE = 0x4E102A4000
DUMP_SHA256 = hashlib.sha256(TEXT).hexdigest()
SOURCE = "Civ7 nnSdk dump/4e102a4000.bin; semantic AArch64 analysis"


def entry(offset, size, **extra):
    prefix_size = min(size, 256)
    value = {
        "offset": offset,
        "bytes": TEXT[offset:offset + prefix_size].hex(),
        "size": size,
        "prefixSize": prefix_size,
        "sha256": hashlib.sha256(TEXT[offset:offset + size]).hexdigest(),
        "validation": "exact dump verification prefix; size and sha256 cover the full function body",
    }
    value.update(extra)
    return value


def write(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n")


def instructions(offset, size):
    return [
        f"{address - BASE:x}: {mnemonic} {operands}".rstrip()
        for address, _, mnemonic, operands in disassemble(TEXT[offset:offset + size], BASE + offset)
    ]


thread_functions = {
    "create": entry(0x142180, 0x220,
        dynamicSymbol="pthread_create (defined symbol 21430, size 0x220)",
        semantics="pthread_create(thread*, attr, entry, arg); null attr uses the default joinable attribute path",
        outputSemantics={
            "status": "RUNTIME_DISCOVERY_REQUIRED",
            "evidence": "0x14235c computes x8=x23&7 and 0x142364 stores it to the output slot. The allocated thread object is 8-byte aligned, so a successful create can return 0 with output 0.",
            "threadPointerFormula": "At 0x142340 x20=x23+0x310; at 0x14234c x8=x21+(w0<<3), where x21 is the entry argument (ownedFrameBase); at 0x142354 x20 is stored at [x8+0x80]. w0 is the helper return at 0x142348 and is not stored in the frame; its value is not statically known.",
            "diagnostic": "Read only owned memory after create returns. Test the bounded diagnostic candidates w0=0..3 at ownedFrameBase+0x80,+0x88,+0x90,+0x98; this probe bound is not a claimed semantic maximum for w0. For each nonzero aligned candidate, query its mapping, then verify [candidate-0x150]==sdk+0x5511b4 and [candidate-0x148]==ownedFrameBase (the thread object's entry/argument at x23+0x1c0/+0x1c8). Stop if none matches; do not call through an unvalidated pointer or change create/default attributes."
        }),
    "join": entry(0x142480, 0xc8,
        dynamicSymbol="pthread_join (defined symbol 21128, size 0xc8)",
        semantics="pthread_join(thread, result**, unused); waits and returns the stored thread result"),
    "exit": entry(0x142410, 0x70,
        status="CONFIRMED_DEFINED_SYMBOL",
        dynamicSymbol="pthread_exit (defined symbol 9614, size 0x70)",
        semantics="save x0 as the thread result at current thread+0x1d0, then signal thread+0x1d8; safe for the existing final frame target"),
    "current": entry(0x137050, 0xc,
        semantics="read current nn::os::ThreadType from TPIDRRO_EL0+0x1f8"),
    "longjmp": entry(0x5511b4, 0x3c,
        semantics="restore x19-x30, SP and d8-d15 from x0; normalize w1; br x30"),
    "loadTable": entry(0x4e094, 0x18,
        semantics="x8=[x21]; x0=x8+(x20<<16); restore x20,x19,x21,x29,x30; ret; frame x20 is zero"),
    "call4": entry(0x359b88, 0x38,
        status="CONFIRMED_SEMANTIC_VARIANT",
        semantics="move x0=x25,x1=x21,x2=x20,x3=x19,x7=x30; ldr x8,[x8,#0x70]; br x8; restore the reference epilogue",
        loadFromSelfOffset=0x70,
        referenceLoadFromSelfOffset=0x68,
        requiredFrameChange="Store call.function at table+0x80 (self pointer table+0x10 plus 0x70); the reference builder stores it at table+0x78."),
    "saveResult": entry(0x28c980, 0x10,
        semantics="store w0 at [x1]; restore x19,x29,x30; ret"),
    "saveResult64": entry(0x19bcc0, 0x10,
        semantics="store x0 at [x1]; restore x19,x29,x30; ret"),
    "tryWait": entry(0x137110, 0x14,
        semantics="nn::os::TryWaitThread wrapper; forwards ThreadType* to the manager implementation"),
    "tryWaitImplementation": entry(0x13e120, 0xb8,
        dynamicSymbol="nn::os::detail::ThreadManagerImplByHorizon::TryWaitForExitThread (defined symbol 9296, size 0xb8)",
        semantics="poll the thread handle with zero timeout; return one when exited and zero when still running, matching native-worker join polling"),
    "sleep": entry(0x137100, 0x4,
        semantics="tail branch through the SDK sleep-thread import thunk"),
}
write("thread-code.json", {
    "source": SOURCE,
    "sha256": DUMP_SHA256,
    "frameCompatibility": {
        "referenceBuilderDropIn": False,
        "requiredChanges": [
            "Apply the call4 table+0x80 target-slot adjustment described in functions.call4.",
            "The direct nn::os lifecycle is NO-GO while CreateThread hangs without returning; do not attempt exitContinuation or DestroyThread as a workaround."
        ],
        "bti": "No BTI C, BTI JC, PACIBSP or RETAB opcode was found in the complete text dump. All selected frame gadgets begin without a BTI landing pad, matching the reference gadget style. Runtime BTI enforcement cannot be established from the dump and requires the normal worker qualification."
    },
    "directNnOs": {
        "status": "NO_GO_CREATE_THREAD_HANG_UNRESOLVED",
        "hardwareBlock": {
            "observation": "Two independent clean Civ7 processes hung inside CreateThread with page-aligned zeroed 0x1000 ThreadType, separate page-aligned 0x14000 stack, priority 20, and the longjmp/frame entry. StartThread was never reached.",
            "identicalPthreadCallee": "pthread_create at 0x1422d0 branches through 0x5e6b30 to the same exported CreateThread at 0x136d50; its start path branches through 0x5e6b40 to the same StartThread at 0x136da0.",
            "staticConclusion": "Object zeroing is sufficient because ThreadManager clears 0x1c0 itself. Stack top is stack base+size. Entry is stored but not executed before return. Resource retry is bounded at ten 10 ms attempts. No direct-input correction or special caller-context requirement is established by the dump.",
            "recommendation": "NO-GO: do not make further direct CreateThread attempts without new evidence locating the blocking call. The previous direct-path recommendation is withdrawn."
        },
        "functions": {
            "create": entry(0x136d50, 0x28,
                dynamicSymbol="nn::os::CreateThread default-core overload (defined symbol 23039, size 0x28)",
                call="CreateThread(thread, entry, argument, stack, stackBytes, priority) -> result; x0=ThreadType*, x1=entry, x2=argument, x3=stack, x4=stackBytes, w5=priority; default core is selected by the manager",
                semantics="forwards to ThreadManager::CreateThread; its default-core overload at 0x13819c sets w7=-2"),
            "start": entry(0x136da0, 0x14,
                dynamicSymbol="nn::os::StartThread (defined symbol 6825, size 0x14)",
                call="StartThread(thread) -> result; x0=ThreadType*"),
            "destroy": entry(0x136d80, 0x14,
                dynamicSymbol="nn::os::DestroyThread (defined symbol 8559, size 0x14)",
                call="DestroyThread(thread) -> result; x0=ThreadType*; call only after TryWaitThread observes exit"),
            "exitContinuation": entry(0x13e094, 0x20,
                status="REQUIRED_FINAL_FRAME_TARGET_FOR_DIRECT_THREADS",
                semantics="normal nn::os bootstrap continuation immediately after blr at 0x13e090; runs the optional exit hook and svcExitThread. Use this instead of pthread_exit so the frame returns through the normal direct-thread path"),
        },
        "threadType": {
            "requestedBytes": 0x400,
            "requestedBytesSupported": False,
            "minimumBytes": 0x601,
            "recommendedBytes": 0x1000,
            "evidence": "ThreadManager::CreateThread at 0x137ea4 clears 0x1c0 bytes and writes fields through ThreadType+0x1b4, plus a flag byte at ThreadType+0x600 (0x137f34). A zeroed 0x400-byte buffer is therefore too small; use a zeroed page-aligned 0x1000-byte owned buffer."
        },
        "stack": {
            "bytes": 0x14000,
            "separateFromThreadType": True,
            "pageAligned": True,
            "evidence": "The direct wrapper forwards caller stack address/size. The low-level creator derives the initial stack context from ThreadType+0x48/+0x50. Use separate page-aligned owned RW memory of the same size as the default pthread stack; do not place it in the 0x1000-byte ThreadType buffer."
        },
        "priority": {
            "value": 20,
            "evidence": "ThreadManager::CreateThread stores w6 as a halfword at ThreadType+0x88 (0x137f0c)."
        },
        "tryWait": {
            "function": "functions.tryWait",
            "implementation": "functions.tryWaitImplementation",
            "runningResult": 0,
            "exitedResult": 1,
            "evidence": "TryWaitForExitThread initializes w20=1 and returns it on a successful synchronization wait; timeout result 0xea01 changes it to zero."
        },
        "cleanup": {
            "requiresPthreadJoin": False,
            "recipe": "After TryWaitThread returns one, read worker results from the owned frame and call DestroyThread. The manager removes the object from its list, unmaps any alias stack, closes the kernel handle, and clears state. Only then release the owned ThreadType and stack buffers.",
            "evidence": "DestroyThreadUnsafe at 0x13e0e4 closes ThreadType+0x1b0; DestroyThreadObject at 0x138340 unlinks and cleans the object. No pthread_join result is required."
        },
        "pthreadExit": {
            "compatible": False,
            "resultFieldSupported": False,
            "evidence": "pthread_exit reads the musl thread object from TPIDRRO_EL0+0x1e0 and stores its result at that object's+0x1d0. Direct CreateThread initializes the nn::os current-thread slot at TPIDRRO_EL0+0x1f8 (0x13e04c) but does not initialize the musl object. Do not use pthread_exit or expect a direct ThreadType+0x1d0 result; use exitContinuation and read owned frame results."
        },
        "affinity": {
            "compatible": True,
            "get": "thread-scheduling-reference.json functions['nn::os::GetThreadCoreMask(int*, unsigned long*, nn::os::ThreadType const*)']",
            "set": "thread-scheduling-reference.json functions['nn::os::SetThreadCoreMask(nn::os::ThreadType*, int, unsigned long)']",
            "evidence": "Both wrappers accept the direct ThreadType* and the detail implementations use the kernel handle at ThreadType+0x1b0. Get/SetThreadCoreMask can be used after CreateThread and before/after StartThread with the direct available-core mask."
        },
        "lifecycle": [
            "NO-GO: do not retry direct CreateThread or progress to StartThread until a concrete correction is identified."
        ]
    },
    "managerListRecovery": {
        "status": "STATICALLY_SUPPORTED_BOUNDED_LIST_WALK",
        "purpose": "Locate the already-created pthread worker without calling CreateThread or using the failed frame-output formula.",
        "layout": {
            "globalManagerPointerOffset": 0xb22280,
            "managerBias": 0xf0,
            "listSentinelOffset": 0x1d0,
            "nextOffset": 0,
            "previousOffset": 8,
            "entryOffset": 0x68,
            "argumentOffset": 0x60,
            "pthreadBaseFromNode": -0x310,
            "pthreadEntryOffset": 0x1c0,
            "pthreadArgumentOffset": 0x1c8,
            "kernelHandleOffset": 0x1b0,
            "managerLockOffset": 0x1c8
        },
        "evidence": "Every public wrapper loads the manager pointer at sdk+0xb22280 and adds 0xf0. Constructor 0x138604 sets manager+0x1d0 to that same sentinel address. Create inserts the ThreadType at manager+0x1d0 before StartThread (0x13804c-0x13806c), storing entry at node+0x68 and argument at node+0x60. pthread_create places this inner ThreadType at pthread_base+0x310 and separately stores entry/argument at pthread_base+0x1c0/+0x1c8. DestroyThreadObject unlinks nodes at 0x138340.",
        "guardedWalk": {
            "maxNodes": 128,
            "steps": [
                "Read manager=read64(sdk+0xb22280)+0xf0; validate a readable mapping covering manager through manager+0x1e8.",
                "Set sentinel=manager+0x1d0 and node=read64(sentinel). Keep a visited-address set.",
                "For at most 128 nodes: stop at sentinel; reject an unaligned node, a duplicate/self-cycle, or a mapping that does not cover node through node+0x608.",
                "Read entry=read64(node+0x68), argument=read64(node+0x60), and next=read64(node+0). Match entry==sdk+0x5511b4 and argument==ownedFrameBase; otherwise continue at next.",
                "For a match, set pthreadBase=node-0x310, validate its mapping through +0x1c8, and require read64(pthreadBase+0x1c0)==entry and read64(pthreadBase+0x1c8)==argument.",
                "Revalidate node and its manager linkage immediately before any native operation. Abort on mismatch rather than following an invalid pointer."
            ],
            "archivedExample": {
                "ownedFrameBase": "0x597cd0f000",
                "note": "This value is ASLR-specific; a new diagnostic must use that run's actual ownedFrameBase."
            }
        },
        "operations": {
            "getCoreMask": "Call 0x1371c0(outIdealCore,outMask,node) and read outMask.",
            "setCoreMask": "Call 0x1371a0(node,0,mask), then verify with GetThreadCoreMask.",
            "tryWait": "Call existing 0x137110(node): 0 means still running, 1 means exited. Do not destroy a gate-blocked worker while it is running.",
            "destroy": "Only after TryWaitThread returns 1, call 0x136d80(node) and require zero. No pthread_join and no new CreateThread call."
        }
    },
    "functions": thread_functions,
})

write("event-code.json", {
    "source": SOURCE,
    "sha256": DUMP_SHA256,
    "functions": {
        "initialize": entry(0x1324e0, 0x28, semantics="initialize an 8-byte light event; auto/manual reset and initial signal state"),
        "finalize": entry(0x132510, 0x8),
        "wait": entry(0x132680, 0x160),
        "tryWait": entry(0x1327e0, 0x54),
        "signal": entry(0x132520, 0x118),
        "clear": entry(0x132640, 0x38),
        "waitAddress": entry(0x168d1c, 0x8, semantics="svc 0x34 WaitForAddress; ret"),
        "signalAddress": entry(0x168d24, 0x8, semantics="svc 0x35 SignalToAddress; ret"),
    },
})

write("timing-code.json", {
    "source": SOURCE,
    "sha256": DUMP_SHA256,
    "functions": {
        "tick": entry(0x137240, 0x8, semantics="mrs x0,cntpct_el0; ret"),
        "frequency": entry(0x137270, 0xc, semantics="return 19200000 (legacy SDK counter-frequency constant)"),
        "priority": entry(0x1370c0, 0x8, semantics="return the current thread priority halfword at ThreadType+0x44"),
    },
    "nativeFrequencyCode": {
        "offset": None,
        "bytes": None,
        "status": "UNRESOLVED",
        "expectedFrequency": 31250000,
        "blocker": "The nnCompatThin/native compatibility module was not dumped. Civ7 module identity cannot be inferred from SmileBASIC's exact 45989888-byte region size. Verify 31250000 Hz at runtime without that size heuristic or dump and identify the module first."
    },
})

write("hash-code.json", {
    **entry(0x4d40, 0x6c,
        dynamicSymbol="nn::crypto::GenerateSha256Hash (defined symbol 5867, size 0x6c)",
        semantics="four-argument SHA-256 wrapper: initialize local context, update(input,count), get hash(output,outputBytes), finalize context",
        identity="Exact defined GenerateSha256Hash symbol; adjacent GenerateSha256 is at 0x4cd0"),
    "source": SOURCE + "; GenerateSha256Hash equivalent",
    "dumpSha256": DUMP_SHA256,
})

scheduling_specs = [
    ("pthread_getaffinity_np", 0x1419e0, 0xe4, "copy the selected thread core mask and zero the remaining cpu_set bytes"),
    ("pthread_setaffinity_np", 0x141ad0, 0x110, "validate and apply a process-available core mask to the selected thread"),
    ("pthread_getschedparam", 0x141be0, 0xc8, "read thread scheduling policy and converted priority"),
    ("pthread_setschedprio", 0x141d80, 0xb4, "validate and set a thread priority"),
    ("nn::os::GetThreadCoreMask(int*, unsigned long*, nn::os::ThreadType const*)", 0x1371c0, 0x1c, "forward core-mask query to the thread manager"),
    ("nn::os::SetThreadCoreMask(nn::os::ThreadType*, int, unsigned long)", 0x1371a0, 0x1c, "forward core-mask update to the thread manager"),
    ("nn::os::GetCurrentCoreNumber()", 0x137150, 0x10, "tail call the current-core manager implementation; 0x137160 is an equivalent alias"),
    ("nn::os::GetThreadAvailableCoreMask()", 0x1371e0, 0x10, "return the unmasked process-available core mask"),
    ("nn::os::detail::ThreadManagerImplByHorizon::GetThreadAvailableCoreMask() const", 0x13e484, 0x40, "svcGetInfo core-mask query with INVALID_HANDLE and current-process pseudo-handle"),
    ("nn::os::detail::ThreadManagerImplByHorizon::GetCurrentCoreNumber() const", 0x13e3e8, 0x4, "tail branch to svcGetCurrentProcessorNumber"),
]
scheduling_functions = {}
for name, offset, size, semantics in scheduling_specs:
    scheduling_functions[name] = entry(offset, size,
        semantics=semantics, instructions=instructions(offset, size))
write("thread-scheduling-reference.json", {
    "source": SOURCE,
    "dumpSha256": DUMP_SHA256,
    "functions": scheduling_functions,
})

DATA_R = (ROOT / "dump/4e10d8d000.bin").read_bytes()
compat_target = int.from_bytes(DATA_R[0xb26900 - 0xae9000:0xb26900 - 0xae9000 + 8], "little")
write("compat-affinity-reference.json", {
    "schemaVersion": 1,
    "mode": "direct-nnSdk",
    "source": SOURCE,
    "symbol": "_ZN2nn2os26GetThreadAvailableCoreMaskEv",
    "availableCoreMask": {
        "config": "thread-scheduling-reference.json",
        "function": "nn::os::GetThreadAvailableCoreMask()",
        **entry(0x1371e0, 0x10, semantics="return the direct process-available core mask"),
        "implementationOffset": 0x13e484,
    },
    "effect": "Use the direct nnSdk process mask and direct nn::os core-mask get/set calls for owned workers. This bypasses the external compatibility mask used inside pthread_setaffinity_np.",
    "pthreadAffinityCompatibility": {
        "gotOffset": 0xb26900,
        "import": entry(0x5e6c50, 0x10,
            semantics="PLT import called by pthread_setaffinity_np before it ANDs the requested mask with the returned value"),
        "target": {
            "capturedAddress": hex(compat_target),
            "offset": None,
            "bytes": None,
            "size": None,
            "status": "UNRESOLVED",
            "blocker": "The external compatibility module is not present in the dumps. Its module-relative target offset, exact expected bytes, and nearby symbol string cannot be validated; capturedAddress is session-absolute and is not an offset."
        },
        "symbolOffsetFromTarget": None,
        "effectOnPthread": "At 0x141afc pthread_setaffinity_np calls the import and at 0x141b00 computes requestedMask &= importedMask. Keeping pthread affinity therefore still requires runtime validation of this target."
    },
    "consumerRequirements": [
        "Replace affinity.cjs GOT/import/target verification with byte verification of the direct available/current/implementation functions in thread-scheduling-reference.json.",
        "In available(), call only the direct available-core-mask function and use that process mask for pinning.",
        "Replace pthread_getaffinity_np/pthread_setaffinity_np in get()/pin() with nn::os::GetThreadCoreMask and nn::os::SetThreadCoreMask. This is required to bypass the compat AND inside pthread_setaffinity_np, not an optional cleanup.",
        "Confirm the direct mask is nonzero and each requested single-core mask is a subset at runtime; verify affinity by reading it back through nn::os::GetThreadCoreMask."
    ],
})
