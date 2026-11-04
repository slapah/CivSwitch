#!/usr/bin/env python3
"""Linear sweep of Civ7 sdk .text: collect BL/B call graph edges, svc table,
ADRP data references (ADD/LDR/LDRB/... pairs). Saves compact JSON index."""
import json, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM

ROOT = r"C:\Users\mike\Documents\kimi\tasks\2026-11-01\18-11-15-7ce4f4b7"
text = open(os.path.join(ROOT, "dump", "4e102a4000.bin"), "rb").read()
BASE = 0x4E102A4000
SIZE = len(text)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True

bl_edges = {}      # target -> [caller_off]
b_edges = {}
svcs = []          # (off, N)
adrp_ref = {}      # insn_off -> referenced module offset (via adrp+add/ldr pair)
ret_after = []     # offsets following ret/retab/br/b (possible fn starts)

insns = md.disasm(text, BASE)
prev_mn = None
prev_off = 0
pend_adrp = {}     # reg -> (off, pageaddr)
for ins in insns:
    off = ins.address - BASE
    mn = ins.mnemonic
    if mn == "bl" and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
        t = ins.operands[0].imm - BASE
        if 0 <= t < SIZE:
            bl_edges.setdefault(t, []).append(off)
    elif mn == "b" and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
        t = ins.operands[0].imm - BASE
        if 0 <= t < SIZE:
            b_edges.setdefault(t, []).append(off)
        ret_after.append(off + 4)
    elif mn == "svc":
        svcs.append((off, ins.operands[0].imm))
    elif mn == "adrp":
        pend_adrp[ins.reg_name(ins.operands[0].reg)] = (off, ins.operands[1].imm)
    elif mn in ("add", "ldr", "ldrb", "ldrh", "ldrsw", "str", "ldrsb", "ldrsh", "strb", "strh"):
        ops = ins.operands
        if mn == "add" and len(ops) == 3 and ops[2].type == ARM64_OP_IMM:
            rn = ins.reg_name(ops[1].reg)
            if rn in pend_adrp:
                ao, page = pend_adrp[rn]
                adrp_ref[ao] = page + ops[2].imm - BASE
        elif len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
            rn = ins.reg_name(ops[1].mem.base)
            if rn in pend_adrp:
                ao, page = pend_adrp[rn]
                adrp_ref[ao] = page + ops[1].mem.disp - BASE
    if mn in ("ret", "retab", "br"):
        ret_after.append(off + 4)
    prev_mn, prev_off = mn, off

out = {
    "bl": {str(k): v for k, v in bl_edges.items()},
    "b": {str(k): v for k, v in b_edges.items()},
    "svc": svcs,
    "adrp": {str(k): v for k, v in adrp_ref.items()},
}
path = os.path.join(ROOT, "port", "xref-index.json")
with open(path, "w") as f:
    json.dump(out, f)
print("bl targets:", len(bl_edges), "b targets:", len(b_edges), "svcs:", len(svcs),
      "adrp refs:", len(adrp_ref))
print("saved", path)
