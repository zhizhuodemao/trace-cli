package com.github.unidbg;

import capstone.api.Instruction;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Locale;

final class RegAccessPrinter {

    private final long address;
    private final Instruction instruction;
    private final short[] accessRegs;
    private boolean forWriteRegs;

    public RegAccessPrinter(long address, Instruction instruction, short[] accessRegs, boolean forWriteRegs) {
        this.address = address;
        this.instruction = instruction;
        this.accessRegs = accessRegs;
        this.forWriteRegs = forWriteRegs;
    }

    public void print(Emulator<?> emulator, Backend backend, StringBuilder builder, long address) {
        if (this.address != address) {
            return;
        }
        for (short reg : accessRegs) {
            int regId = instruction.mapToUnicornReg(reg);
            if (emulator.is32Bit()) {
                if ((regId >= ArmConst.UC_ARM_REG_R0 && regId <= ArmConst.UC_ARM_REG_R12) ||
                        regId == ArmConst.UC_ARM_REG_LR || regId == ArmConst.UC_ARM_REG_SP ||
                        regId == ArmConst.UC_ARM_REG_CPSR) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == ArmConst.UC_ARM_REG_CPSR) {
                        Cpsr cpsr = Cpsr.getArm(backend);
                        builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0,
                                cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0,
                                cpsr.isOverflow() ? 1 : 0));
                    } else {
                        int value = backend.reg_read(regId).intValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                    }
                }
            } else {
                if ((regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) ||
                        (regId >= Arm64Const.UC_ARM64_REG_X29 && regId <= Arm64Const.UC_ARM64_REG_SP)) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == Arm64Const.UC_ARM64_REG_NZCV) {
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        if (cpsr.isA32()) {
                            builder.append(String.format(Locale.US, " cpsr: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0,
                                    cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0,
                                    cpsr.isOverflow() ? 1 : 0));
                        } else {
                            builder.append(String.format(Locale.US, " nzcv: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0,
                                    cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0,
                                    cpsr.isOverflow() ? 1 : 0));
                        }
                    } else {
                        long value = backend.reg_read(regId).longValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value));
                    }
                } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    int value = backend.reg_read(regId).intValue();
                    builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                } else if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    try {
                        byte[] vec = backend.reg_read_vector(regId);
                        if (vec != null && vec.length >= 16) {
                            // Output as 128-bit hex: high 64 bits then low 64 bits (big-endian display)
                            StringBuilder hex = new StringBuilder();
                            for (int i = vec.length - 1; i >= 0; i--) {
                                hex.append(String.format("%02x", vec[i] & 0xFF));
                            }
                            // Always output full 32 hex digits for 128-bit Q registers
                            // (no leading zero stripping — parser needs exact 128-bit width)
                            builder.append(' ').append(instruction.regName(reg)).append("=0x").append(hex.toString());
                        }
                    } catch (Exception ignored) {}
                } else if (regId >= Arm64Const.UC_ARM64_REG_D0 && regId <= Arm64Const.UC_ARM64_REG_D31) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    try {
                        // D registers are the lower 64 bits of Q registers
                        int qRegId = Arm64Const.UC_ARM64_REG_Q0 + (regId - Arm64Const.UC_ARM64_REG_D0);
                        byte[] vec = backend.reg_read_vector(qRegId);
                        if (vec != null && vec.length >= 8) {
                            long lo = 0;
                            for (int i = 7; i >= 0; i--) {
                                lo = (lo << 8) | (vec[i] & 0xFFL);
                            }
                            builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(lo));
                        }
                    } catch (Exception ignored) {}
                } else if (regId >= Arm64Const.UC_ARM64_REG_S0 && regId <= Arm64Const.UC_ARM64_REG_S31) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    try {
                        int qRegId = Arm64Const.UC_ARM64_REG_Q0 + (regId - Arm64Const.UC_ARM64_REG_S0);
                        byte[] vec = backend.reg_read_vector(qRegId);
                        if (vec != null && vec.length >= 4) {
                            int val = (vec[0] & 0xFF) | ((vec[1] & 0xFF) << 8) | ((vec[2] & 0xFF) << 16) | ((vec[3] & 0xFF) << 24);
                            builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(val & 0xffffffffL));
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
    }

}
