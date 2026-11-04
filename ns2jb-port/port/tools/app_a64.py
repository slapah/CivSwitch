import struct


def sx(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def reg(number, width=64, sp=False):
    if number == 31:
        return "sp" if sp else ("wzr" if width == 32 else "xzr")
    return ("w" if width == 32 else "x") + str(number)


def regs(number, width=64):
    return "sp" if number == 31 else reg(number, width)


def mem(word, width, pair=False):
    rn = (word >> 5) & 31
    scale = 8 if width == 64 else 4
    imm = sx((word >> 15) & 0x7f, 7) * scale if pair else ((word >> 10) & 0xfff) * scale
    base = regs(rn, 64)
    suffix = f", #{imm:#x}" if imm else ""
    mode = (word >> 23) & 3
    if pair and mode == 1:
        return f"[{base}], #{imm:#x}"
    if pair and mode == 3:
        return f"[{base}, #{imm:#x}]!"
    return f"[{base}{suffix}]"


def decode(word, pc):
    top = word >> 26
    if top in (0x05, 0x25):
        target = pc + sx(word & 0x3ffffff, 26) * 4
        return ("bl" if top == 0x25 else "b", f"#0x{target:x}")
    if word & 0x7e000000 == 0x54000000:
        target = pc + sx((word >> 5) & 0x7ffff, 19) * 4
        conditions = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        return ("b." + conditions[word & 15], f"#0x{target:x}")
    if word & 0x7e000000 == 0x34000000:
        width = 64 if word >> 31 else 32
        target = pc + sx((word >> 5) & 0x7ffff, 19) * 4
        return ("cbnz" if (word >> 24) & 1 else "cbz", f"{reg(word & 31, width)}, #0x{target:x}")
    if word & 0x7e000000 == 0x36000000:
        width = 64 if word >> 31 else 32
        bit = ((word >> 19) & 0x18) | ((word >> 31) & 1) * 32
        target = pc + sx((word >> 5) & 0x3fff, 14) * 4
        return ("tbnz" if (word >> 24) & 1 else "tbz", f"{reg(word & 31, width)}, #{bit}, #0x{target:x}")
    if word == 0xd65f03c0:
        return "ret", ""
    if word & 0xfffffc1f == 0xd61f0000:
        return "br", reg((word >> 5) & 31)
    if word & 0xfffffc1f == 0xd63f0000:
        return "blr", reg((word >> 5) & 31)
    if word & 0x9f000000 in (0x10000000, 0x90000000):
        imm = sx(((word >> 5) & 0x7ffff) << 2 | (word >> 29) & 3, 21)
        if word & 0x9f000000 == 0x90000000:
            target = (pc & ~0xfff) + (imm << 12)
            return "adrp", f"{reg(word & 31)}, #0x{target:x}"
        return "adr", f"{reg(word & 31)}, #0x{pc + imm:x}"
    if word & 0x1f800000 == 0x12800000 or word & 0x1f800000 == 0x52800000:
        width = 64 if word >> 31 else 32
        kind = (word >> 29) & 3
        mnemonic = {0: "movn", 2: "movz", 3: "movk"}.get(kind, "mov")
        shift = ((word >> 21) & 3) * 16
        immediate = (word >> 5) & 0xffff
        text = f"{reg(word & 31, width)}, #{immediate:#x}"
        if shift:
            text += f", lsl #{shift}"
        return mnemonic, text
    if word & 0x1f000000 == 0x11000000:
        width = 64 if word >> 31 else 32
        sub = (word >> 30) & 1
        flags = (word >> 29) & 1
        mnemonic = ("sub" if sub else "add") + ("s" if flags else "")
        rd, rn = word & 31, (word >> 5) & 31
        immediate = ((word >> 10) & 0xfff) << (12 if (word >> 22) & 1 else 0)
        if flags and rd == 31:
            return "cmp" if sub else "cmn", f"{regs(rn, width)}, #{immediate:#x}"
        return mnemonic, f"{regs(rd, width)}, {regs(rn, width)}, #{immediate:#x}"
    if word & 0x1f000000 == 0x0a000000 and (word >> 21) & 1 == 0:
        width = 64 if word >> 31 else 32
        rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
        if ((word >> 29) & 3) == 1 and rn == 31 and ((word >> 10) & 0x3f) == 0 and ((word >> 22) & 3) == 0:
            return "mov", f"{reg(rd, width)}, {reg(rm, width)}"
    if word & 0x3e000000 == 0x28000000:
        width = 64 if word >> 31 else 32
        load = (word >> 22) & 1
        pair = not ((word >> 23) & 1)
        if pair:
            mnemonic = ("ldp" if load else "stp")
            rt, rt2 = word & 31, (word >> 10) & 31
            return mnemonic, f"{reg(rt, width)}, {reg(rt2, width)}, {mem(word, width, True)}"
    if word & 0x3b000000 == 0x39000000:
        size = (word >> 30) & 3
        width = 8 << size
        load = (word >> 22) & 1
        mnemonic = ("ldr" if load else "str") + {8: "b", 16: "h", 32: "", 64: ""}[width]
        return mnemonic, f"{reg(word & 31, min(width, 64))}, {mem(word, width)}"
    if word & 0x3b000000 == 0x18000000:
        width = 64 if (word >> 30) & 1 else 32
        target = pc + sx((word >> 5) & 0x7ffff, 19) * 4
        return "ldr", f"{reg(word & 31, width)}, #0x{target:x}"
    if word & 0x1f000000 == 0x1a000000 and ((word >> 10) & 3) == 0:
        width = 64 if word >> 31 else 32
        rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
        cond = (word >> 12) & 15
        op = (word >> 30) & 3
        mnemonic = {0: "csel", 1: "csinc", 2: "csinv", 3: "csneg"}.get(op, "csel")
        return mnemonic, f"{reg(rd, width)}, {reg(rn, width)}, {reg(rm, width)}, #{cond}"
    if word == 0xd503201f:
        return "nop", ""
    if word & 0xfffff01f == 0xd503301f:
        return "clrex", ""
    if word & 0xfffff0ff == 0xd50330bf:
        return "dmb", f"#0x{(word >> 8) & 15:x}"
    if word & 0xfffff0ff == 0xd50330df:
        return "isb", f"#0x{(word >> 8) & 15:x}"
    if word & 0xfffff0ff == 0xd50330ff:
        return "dsb", f"#0x{(word >> 8) & 15:x}"
    if word & 0xffe00000 == 0xd5300000:
        return "mrs", f"{reg(word & 31)}, sys_{(word >> 5) & 0xffff:x}"
    if word & 0xffe00000 == 0xd5100000:
        return "msr", f"sys_{(word >> 5) & 0xffff:x}, {reg(word & 31)}"
    if word & 0xffc00000 == 0x39400000:
        return "ldrb", f"{reg(word & 31, 32)}, {mem(word, 8)}"
    if word & 0xffc00000 == 0x39000000:
        return "strb", f"{reg(word & 31, 32)}, {mem(word, 8)}"
    if word & 0xffc00000 == 0x79400000:
        return "ldrh", f"{reg(word & 31, 32)}, {mem(word, 16)}"
    if word & 0xffc00000 == 0x79000000:
        return "strh", f"{reg(word & 31, 32)}, {mem(word, 16)}"
    if word & 0xffc00000 == 0xb9400000:
        return "ldr", f"{reg(word & 31, 32)}, {mem(word, 32)}"
    if word & 0xffc00000 == 0xb9000000:
        return "str", f"{reg(word & 31, 32)}, {mem(word, 32)}"
    if word & 0xffc00000 == 0xf9400000:
        return "ldr", f"{reg(word & 31)}, {mem(word, 64)}"
    if word & 0xffc00000 == 0xf9000000:
        return "str", f"{reg(word & 31)}, {mem(word, 64)}"
    if word & 0x7f000000 == 0x71000000:
        width = 64 if word >> 31 else 32
        return "cmp", f"{reg((word >> 5) & 31, width)}, #{(word >> 10) & 0xfff:#x}"
    return ".word", f"0x{word:08x}"


def disassemble(data, pc=0):
    for offset in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, offset)[0]
        address = pc + offset
        mnemonic, operands = decode(word, address)
        yield address, word, mnemonic, operands
