#include "vm.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define TB_NOINLINE __attribute__((noinline))
#else
#define TB_NOINLINE
#endif

static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    va_list ap;

    if (err == NULL || err_len == 0) {
        return;
    }

    va_start(ap, fmt);
    (void)vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

static int is_in_bounds(uint32_t addr, uint32_t width) {
    if (width == 0 || addr > (TB_MEM_SIZE - width)) {
        return 0;
    }
    return 1;
}

static int is_data_writable(uint32_t addr, uint32_t width) {
    if (!is_in_bounds(addr, width)) {
        return 0;
    }
    if (addr < TB_STACK_BASE || (addr + width) > TB_STACK_END) {
        return 0;
    }
    return 1;
}

static uint32_t read_u32_volatile(const volatile uint8_t *src) {
    uint32_t v = 0;
    v |= (uint32_t)src[0];
    v |= ((uint32_t)src[1]) << 8;
    v |= ((uint32_t)src[2]) << 16;
    v |= ((uint32_t)src[3]) << 24;
    return v;
}

static void write_u32_volatile(volatile uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v & 0xffu);
    dst[1] = (uint8_t)((v >> 8) & 0xffu);
    dst[2] = (uint8_t)((v >> 16) & 0xffu);
    dst[3] = (uint8_t)((v >> 24) & 0xffu);
}

static int32_t sign_extend(uint32_t value, uint32_t bits) {
    uint32_t sign = 1u << (bits - 1u);
    return (int32_t)((value ^ sign) - sign);
}

static TB_NOINLINE void cache_touch(Vm *vm, uint32_t addr) {
    uint32_t line_index = (addr / TB_CACHE_LINE_SIZE) % TB_CACHE_NUM_LINES;
    uint32_t tag = addr / TB_CACHE_LINE_SIZE;
    CacheLine *line = &vm->l1[line_index];

    if (line->valid && line->tag == tag) {
        vm->cycle += TB_HIT_LATENCY;
        return;
    }

    line->valid = 1;
    line->tag = tag;
    vm->cycle += TB_MISS_LATENCY;
}

static TB_NOINLINE void cache_flush(Vm *vm, uint32_t addr) {
    uint32_t line_index = (addr / TB_CACHE_LINE_SIZE) % TB_CACHE_NUM_LINES;
    vm->l1[line_index].valid = 0;
    vm->cycle += TB_FLUSH_LATENCY;
}

static VmStatus vm_load32_data(Vm *vm, uint32_t addr, uint32_t *out, char *err, size_t err_len) {
    if ((addr & 0x3u) != 0) {
        set_err(err, err_len, "misaligned load at 0x%08x", addr);
        return VM_TRAP;
    }
    if (!is_in_bounds(addr, 4)) {
        set_err(err, err_len, "out-of-bounds load at 0x%08x", addr);
        return VM_TRAP;
    }

    cache_touch(vm, addr);
    *out = read_u32_volatile(vm->mem + addr);
    return VM_OK;
}

static VmStatus vm_store32_data(Vm *vm, uint32_t addr, uint32_t value, char *err, size_t err_len) {
    if ((addr & 0x3u) != 0) {
        set_err(err, err_len, "misaligned store at 0x%08x", addr);
        return VM_TRAP;
    }
    if (!is_data_writable(addr, 4)) {
        set_err(err, err_len, "write denied at 0x%08x", addr);
        return VM_TRAP;
    }

    cache_touch(vm, addr);
    write_u32_volatile(vm->mem + addr, value);
    return VM_OK;
}

static inline void set_reg(Vm *vm, uint32_t reg, uint32_t value) {
    if (reg != 0 && reg < TB_NUM_REGS) {
        vm->regs[reg] = value;
    }
}

static inline int reg_ok(uint32_t reg) {
    return reg < TB_NUM_REGS;
}

static inline int32_t decode_imm_i(uint32_t inst) {
    return sign_extend((inst >> 20) & 0x0fffu, 12);
}

static inline int32_t decode_imm_s(uint32_t inst) {
    uint32_t imm = ((inst >> 25) << 5) | ((inst >> 7) & 0x1fu);
    return sign_extend(imm, 12);
}

static inline int32_t decode_imm_b(uint32_t inst) {
    uint32_t imm = 0;
    imm |= ((inst >> 31) & 0x1u) << 12;
    imm |= ((inst >> 7) & 0x1u) << 11;
    imm |= ((inst >> 25) & 0x3fu) << 5;
    imm |= ((inst >> 8) & 0x0fu) << 1;
    return sign_extend(imm, 13);
}

static inline int32_t decode_imm_j(uint32_t inst) {
    uint32_t imm = 0;
    imm |= ((inst >> 31) & 0x1u) << 20;
    imm |= ((inst >> 12) & 0x0ffu) << 12;
    imm |= ((inst >> 20) & 0x1u) << 11;
    imm |= ((inst >> 21) & 0x03ffu) << 1;
    return sign_extend(imm, 21);
}

static VmStatus trigger_secret(Vm *vm) {
    uint32_t index = vm->regs[1];
    uint8_t sink = 0;

    if (index >= vm->real_flag_len) {
        return VM_OK;
    }

    uint8_t symbol = (uint8_t)vm->real_flag[index];
    uint32_t addr = TB_PROBE_BASE + ((uint32_t)symbol * TB_CACHE_LINE_SIZE);

    if (!is_in_bounds(addr, 1)) {
        return VM_TRAP;
    }

    cache_touch(vm, addr);
    sink ^= vm->mem[addr];
    (void)sink;

    return VM_OK;
}

void vm_init(Vm *vm, const char *real_flag, uint32_t flag_len) {
    uint32_t b;
    uint32_t j;

    (void)memset(vm, 0, sizeof(*vm));
    vm->real_flag = real_flag;
    vm->real_flag_len = flag_len;
    vm->pc = TB_CODE_BASE;

    /* Solver-friendly startup constants without exposing secret data. */
    vm->regs[2] = TB_PROBE_BASE;
    vm->regs[3] = TB_CACHE_LINE_SIZE;
    vm->regs[4] = TB_PROBE_LINES;
    vm->regs[5] = TB_STACK_BASE;

    for (b = 0; b < TB_PROBE_LINES; b++) {
        uint32_t base = TB_PROBE_BASE + (b * TB_CACHE_LINE_SIZE);
        for (j = 0; j < TB_CACHE_LINE_SIZE; j++) {
            vm->mem[base + j] = (uint8_t)((b ^ j) & 0xffu);
        }
    }
}

VmStatus vm_load_code(Vm *vm, const uint8_t *code, size_t code_size, uint32_t entry_offset, char *err, size_t err_len) {
    size_t i;

    if (code == NULL || code_size == 0) {
        set_err(err, err_len, "empty code image");
        return VM_ERROR;
    }
    if (code_size > TB_CODE_REGION_SIZE) {
        set_err(err, err_len, "code size %zu exceeds max %u", code_size, TB_CODE_REGION_SIZE);
        return VM_ERROR;
    }
    if (entry_offset >= code_size) {
        set_err(err, err_len, "entry offset %u outside code image", entry_offset);
        return VM_ERROR;
    }

    for (i = 0; i < TB_CODE_REGION_SIZE; i++) {
        vm->mem[TB_CODE_BASE + i] = 0;
    }
    for (i = 0; i < code_size; i++) {
        vm->mem[TB_CODE_BASE + i] = code[i];
    }

    vm->pc = TB_CODE_BASE + entry_offset;
    return VM_OK;
}

VmStatus vm_step(Vm *vm, char *err, size_t err_len) {
    uint32_t inst;
    uint32_t opcode;
    uint32_t rd;
    uint32_t rs1;
    uint32_t rs2;
    uint32_t funct3;
    uint32_t funct7;
    uint32_t next_pc;

    if ((vm->pc & 0x3u) != 0) {
        set_err(err, err_len, "unaligned pc 0x%08x", vm->pc);
        return VM_TRAP;
    }
    if (vm->pc < TB_CODE_BASE || vm->pc > (TB_CODE_END - 4)) {
        set_err(err, err_len, "pc outside code region: 0x%08x", vm->pc);
        return VM_TRAP;
    }

    inst = read_u32_volatile(vm->mem + vm->pc);
    opcode = inst & 0x7fu;
    rd = (inst >> 7) & 0x1fu;
    funct3 = (inst >> 12) & 0x7u;
    rs1 = (inst >> 15) & 0x1fu;
    rs2 = (inst >> 20) & 0x1fu;
    funct7 = (inst >> 25) & 0x7fu;

    vm->cycle += TB_BASE_INST_COST;
    next_pc = vm->pc + 4;

    if (inst == 0u) {
        vm->halted = 1;
        return VM_HALTED;
    }

    switch (opcode) {
        case 0x37:
            if (!reg_ok(rd)) {
                set_err(err, err_len, "rd out of range in LUI 0x%08x", inst);
                return VM_TRAP;
            }
            set_reg(vm, rd, inst & 0xfffff000u);
            break;

        case 0x33: {
            if (!reg_ok(rd) || !reg_ok(rs1) || !reg_ok(rs2)) {
                set_err(err, err_len, "register out of range in R-type 0x%08x", inst);
                return VM_TRAP;
            }
            uint32_t lhs = vm->regs[rs1];
            uint32_t rhs = vm->regs[rs2];
            if (funct3 == 0x0u && funct7 == 0x00u) {
                set_reg(vm, rd, lhs + rhs);
            } else if (funct3 == 0x0u && funct7 == 0x20u) {
                set_reg(vm, rd, lhs - rhs);
            } else if (funct3 == 0x4u && funct7 == 0x00u) {
                set_reg(vm, rd, lhs ^ rhs);
            } else if (funct3 == 0x6u && funct7 == 0x00u) {
                set_reg(vm, rd, lhs | rhs);
            } else if (funct3 == 0x7u && funct7 == 0x00u) {
                set_reg(vm, rd, lhs & rhs);
            } else {
                set_err(err, err_len, "unsupported R-type instruction 0x%08x", inst);
                return VM_TRAP;
            }
            break;
        }

        case 0x13:
            if (!reg_ok(rd) || !reg_ok(rs1)) {
                set_err(err, err_len, "register out of range in ADDI 0x%08x", inst);
                return VM_TRAP;
            }
            if (funct3 != 0x0u) {
                set_err(err, err_len, "unsupported I-type ALU instruction 0x%08x", inst);
                return VM_TRAP;
            }
            set_reg(vm, rd, (uint32_t)((int32_t)vm->regs[rs1] + decode_imm_i(inst)));
            break;

        case 0x03:
            if (!reg_ok(rd) || !reg_ok(rs1)) {
                set_err(err, err_len, "register out of range in load 0x%08x", inst);
                return VM_TRAP;
            }
            if (funct3 != 0x2u) {
                set_err(err, err_len, "unsupported load instruction 0x%08x", inst);
                return VM_TRAP;
            }
            {
                uint32_t value = 0;
                uint32_t ea = (uint32_t)((int32_t)vm->regs[rs1] + decode_imm_i(inst));
                VmStatus status = vm_load32_data(vm, ea, &value, err, err_len);
                if (status != VM_OK) {
                    return status;
                }
                set_reg(vm, rd, value);
            }
            break;

        case 0x23:
            if (!reg_ok(rs1) || !reg_ok(rs2)) {
                set_err(err, err_len, "register out of range in store 0x%08x", inst);
                return VM_TRAP;
            }
            if (funct3 != 0x2u) {
                set_err(err, err_len, "unsupported store instruction 0x%08x", inst);
                return VM_TRAP;
            }
            {
                uint32_t ea = (uint32_t)((int32_t)vm->regs[rs1] + decode_imm_s(inst));
                VmStatus status = vm_store32_data(vm, ea, vm->regs[rs2], err, err_len);
                if (status != VM_OK) {
                    return status;
                }
            }
            break;

        case 0x63: {
            if (!reg_ok(rs1) || !reg_ok(rs2)) {
                set_err(err, err_len, "register out of range in branch 0x%08x", inst);
                return VM_TRAP;
            }
            int take = 0;
            int32_t imm = decode_imm_b(inst);
            if (funct3 == 0x0u) {
                take = (vm->regs[rs1] == vm->regs[rs2]);
            } else if (funct3 == 0x1u) {
                take = (vm->regs[rs1] != vm->regs[rs2]);
            } else {
                set_err(err, err_len, "unsupported branch instruction 0x%08x", inst);
                return VM_TRAP;
            }
            if (take) {
                next_pc = (uint32_t)((int32_t)vm->pc + imm);
            }
            break;
        }

        case 0x6f: {
            if (!reg_ok(rd)) {
                set_err(err, err_len, "rd out of range in JAL 0x%08x", inst);
                return VM_TRAP;
            }
            int32_t imm = decode_imm_j(inst);
            set_reg(vm, rd, vm->pc + 4);
            next_pc = (uint32_t)((int32_t)vm->pc + imm);
            break;
        }

        case 0x0b:
            if (funct3 == 0x0u) {
                if (!reg_ok(rd)) {
                    set_err(err, err_len, "rd out of range in RDTSC 0x%08x", inst);
                    return VM_TRAP;
                }
                set_reg(vm, rd, (uint32_t)(vm->cycle & 0xffffffffu));
            } else if (funct3 == 0x1u) {
                if (!reg_ok(rs1)) {
                    set_err(err, err_len, "rs1 out of range in CLFLUSH 0x%08x", inst);
                    return VM_TRAP;
                }
                cache_flush(vm, vm->regs[rs1]);
            } else if (funct3 == 0x2u) {
                VmStatus status = trigger_secret(vm);
                if (status != VM_OK) {
                    set_err(err, err_len, "secret trigger failed");
                    return status;
                }
            } else if (funct3 == 0x3u) {
                if (!reg_ok(rs1)) {
                    set_err(err, err_len, "rs1 out of range in PRINT 0x%08x", inst);
                    return VM_TRAP;
                }
                (void)printf("%d\n", (int32_t)vm->regs[rs1]);
                (void)fflush(stdout);
            } else {
                set_err(err, err_len, "unsupported custom instruction 0x%08x", inst);
                return VM_TRAP;
            }
            break;

        default:
            set_err(err, err_len, "illegal opcode in instruction 0x%08x", inst);
            return VM_TRAP;
    }

    if ((next_pc & 0x3u) != 0) {
        set_err(err, err_len, "control flow to unaligned pc 0x%08x", next_pc);
        return VM_TRAP;
    }

    vm->pc = next_pc;
    return VM_OK;
}

VmStatus vm_run(Vm *vm, uint64_t max_steps, char *err, size_t err_len) {
    uint64_t steps;

    for (steps = 0; steps < max_steps; steps++) {
        VmStatus status;
        if (vm->halted) {
            return VM_HALTED;
        }

        status = vm_step(vm, err, err_len);
        if (status == VM_OK) {
            continue;
        }
        return status;
    }

    set_err(err, err_len, "step limit reached (%llu)", (unsigned long long)max_steps);
    return VM_TRAP;
}
