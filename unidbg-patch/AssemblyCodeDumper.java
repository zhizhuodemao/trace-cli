package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import capstone.api.arm64.MemType;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.InstructionVisitor;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

    private final Emulator<?> emulator;

    public AssemblyCodeDumper(Emulator<?> emulator, long begin, long end, TraceCodeListener listener) {
        super();

        this.emulator = emulator;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;

        Memory memory = emulator.getMemory();
        if (begin > end) {
            maxLengthLibraryName = memory.getMaxLengthLibraryName().length();
        } else {
            int value = 0;
            for (Module module : memory.getLoadedModules()) {
                long min = Math.max(begin, module.base);
                long max = Math.min(end, module.base + module.size);
                if (min < max) {
                    int length = module.name.length();
                    if (length > value) {
                        value = length;
                    }
                }
            }
            maxLengthLibraryName = value;
        }
    }

    private final long traceBegin, traceEnd;
    private final TraceCodeListener listener;
    private final int maxLengthLibraryName;

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        if (this.unHook != null) {
            throw new IllegalStateException();
        }
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

    @Override
    public void stopTrace() {
        detach();
        IOUtils.close(redirect);
        redirect = null;
    }

    private boolean canTrace(long address) {
        return (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    private PrintStream redirect;

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    private RegAccessPrinter lastInstructionWritePrinter;

    // Delayed SIMD memory read: record pending store address/size from previous instruction
    private long pendingMemAddr;
    private int pendingMemSize;
    private boolean hasPendingMem;

    @Override
    public void hook(final Backend backend, final long address, final int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.err;
                if (redirect != null) {
                    out = redirect;
                }
                Instruction[] insns = emulator.printAssemble(out, address, size, maxLengthLibraryName, new InstructionVisitor() {
                    @Override
                    public void visitLast(StringBuilder builder) {
                        if (lastInstructionWritePrinter != null) {
                            lastInstructionWritePrinter.print(emulator, backend, builder, address);
                        }
                        // Delayed mem read: previous SIMD store has now executed, read the memory
                        if (hasPendingMem) {
                            try {
                                byte[] data = backend.mem_read(pendingMemAddr, pendingMemSize);
                                StringBuilder hex = new StringBuilder();
                                for (int i = 0; i < data.length; i++) {
                                    hex.append(String.format("%02x", data[i] & 0xFF));
                                }
                                builder.append(String.format(" data[0x%x]=0x%s", pendingMemAddr, hex.toString()));
                            } catch (Exception ignored) {}
                            hasPendingMem = false;
                        }
                    }
                    @Override
                    public void visit(StringBuilder builder, Instruction ins) {
                        hookMemoryAccess(backend, ins, builder);

                        RegsAccess regsAccess = ins.regsAccess();
                        if (regsAccess != null) {
                            short[] regsRead = regsAccess.getRegsRead();
                            RegAccessPrinter readPrinter = new RegAccessPrinter(address, ins, regsRead, false);
                            readPrinter.print(emulator, backend, builder, address);

                            short[] regWrite = regsAccess.getRegsWrite();
                            if (regWrite.length > 0) {
                                lastInstructionWritePrinter = new RegAccessPrinter(address + size, ins, regWrite, true);
                            }
                        }
                    }
                });
                if (listener != null) {
                    if (insns == null || insns.length != 1) {
                        throw new IllegalStateException("insns=" + Arrays.toString(insns));
                    }
                    listener.onInstruction(emulator, address, insns[0]);
                }
            } catch (BackendException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final Pattern LOAD_PATTERN = Pattern.compile(
            "^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldur|ldurb|ldurh|ldursb|ldursh|ldursw|ldp|ldpsw|ldnp|ldaxr|ldxr|ldaxp|ldxp)($|\\s).*");
    private static final Pattern STORE_PATTERN = Pattern.compile(
            "^(str|strb|strh|stur|sturb|sturh|stp|stnp|stlr|stlrb|stlrh|stxr|stlxr|stxp|stlxp)($|\\s).*");

    private void hookMemoryAccess(Backend backend, Instruction ins, StringBuilder builder) {
        try {
            String mnemonic = ins.getMnemonic();
            if (mnemonic == null) return;
            mnemonic = mnemonic.toLowerCase();

            OpInfo opInfo = (OpInfo) ins.getOperands();
            Operand[] operands = opInfo.getOperands();
            Operand memOperand = null;

            for (Operand op : operands) {
                int t = op.getType();
                if (t == Arm64_const.ARM64_OP_MEM || t == Arm_const.ARM_OP_MEM) {
                    memOperand = op;
                    break;
                }
            }

            if (memOperand == null) return;

            String accessType;
            if (LOAD_PATTERN.matcher(mnemonic).matches()) {
                accessType = "READ";
            } else if (STORE_PATTERN.matcher(mnemonic).matches()) {
                accessType = "WRITE";
            } else if (mnemonic.startsWith("ld")) {
                accessType = "READ";
            } else if (mnemonic.startsWith("st")) {
                accessType = "WRITE";
            } else {
                return;
            }

            MemType mem = memOperand.getValue().getMem();

            long baseValue = 0;
            try {
                if (mem.getBase() != 0) {
                    int unicornRegId = ins.mapToUnicornReg(mem.getBase());
                    baseValue = backend.reg_read(unicornRegId).longValue();
                }
            } catch (Exception ignored) {}

            long indexValue = 0;
            try {
                if (mem.getIndex() != 0) {
                    int unicornRegId = ins.mapToUnicornReg(mem.getIndex());
                    indexValue = backend.reg_read(unicornRegId).longValue();
                }
            } catch (Exception ignored) {}

            long shiftedIndex = indexValue;
            try {
                if (memOperand.getShift() != null && memOperand.getShift().getValue() != 0) {
                    shiftedIndex = indexValue << memOperand.getShift().getValue();
                }
            } catch (Throwable ignored) {}

            long absAddr = baseValue + shiftedIndex + mem.getDisp();
            builder.append(String.format(" ; mem[%s] abs=0x%x", accessType, absAddr));

            // For SIMD WRITE operations, schedule a delayed mem_read on next instruction
            // (reg_read_vector returns stale values in CodeHook, so we read memory after execution)
            if ("WRITE".equals(accessType)) {
                // Determine store size from the first data register operand
                int storeSize = 0;
                for (Operand op : operands) {
                    if (op == memOperand) continue;
                    int opType = op.getType();
                    if (opType == Arm64_const.ARM64_OP_REG) {
                        int capReg = op.getValue().getReg();
                        try {
                            int unicornId = ins.mapToUnicornReg(capReg);
                            if (unicornId >= Arm64Const.UC_ARM64_REG_Q0 && unicornId <= Arm64Const.UC_ARM64_REG_Q31) {
                                storeSize += 16;
                            } else if (unicornId >= Arm64Const.UC_ARM64_REG_D0 && unicornId <= Arm64Const.UC_ARM64_REG_D31) {
                                storeSize += 8;
                            } else if (unicornId >= Arm64Const.UC_ARM64_REG_S0 && unicornId <= Arm64Const.UC_ARM64_REG_S31) {
                                storeSize += 4;
                            }
                        } catch (Exception ignored) {}
                    }
                }
                if (storeSize > 0) {
                    pendingMemAddr = absAddr;
                    pendingMemSize = storeSize;
                    hasPendingMem = true;
                }
            }
        } catch (Exception ignored) {}
    }

}
