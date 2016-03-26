#include "binflow.h"

#define MAX_ARGS 6
#define EDI 0
#define ESI 1
#define EDX 2
#define ECX 3
#define R8D 4
#define R9D 5

struct options opts;

char *get_fn_by_range(handle_t *h, uint64_t vaddr)
{
    char *buf = heapAlloc(512);

    for (int i = 0; i < h->lsc; i++) {
        if (vaddr >= h->lsyms[i].value && vaddr < h->lsyms[i].value + h->lsyms[i].size) {
            strncpy(buf, h->lsyms[i].name, sizeof(buf) - 3);
            strcat(buf, "()");
            return buf;
        }
    }
    return NULL;
}
static char *get_fn_name(handle_t *h, uint64_t vaddr)
{
    for (int i = 0; i < h->dsc; i++) {
        if (vaddr == h->dsyms[i].value)
            return h->dsyms[i].name;
    }

    for (int i = 0; i < h->lsc; i++) {
        if (vaddr == h->lsyms[i].value)
            return h->lsyms[i].name;
    }

    return NULL;
}

static bool fn_is_local(handle_t *h, const char *name)
{
    for (int i = 0; i < h->lsc; i++)
        if (!strcmp(h->lsyms[i].name, name))
            return true;

    for (int i = 0; i < h->dsc; i++)
        if (!strcmp(h->dsyms[i].name, name))
            return false;

    if (!strncasecmp(name, "sub_", 4))
        return true;

    return false;
}

static int check_for_reg(cs_insn insn, int reg)
{
    cs_detail *detail = insn.detail;

    switch (reg) {
    case EDI:
        if (detail->x86.operands[0].reg == X86_REG_EDI || detail->x86.operands[0].reg == X86_REG_RDI)
            return 1;
        else
            return 0;
        break;
    case ESI:
        if (detail->x86.operands[0].reg == X86_REG_ESI || detail->x86.operands[0].reg == X86_REG_RSI)
            return 1;
        else
            return 0;
        break;
    case EDX:
        if (detail->x86.operands[0].reg == X86_REG_EDX || detail->x86.operands[0].reg == X86_REG_RDX)
            return 1;
        else
            return 0;
        break;
    case ECX:
        if (detail->x86.operands[0].reg == X86_REG_ECX || detail->x86.operands[0].reg == X86_REG_RCX)
            return 1;
        else
            return 0;
        break;
    case R8D:
        if (detail->x86.operands[0].reg == X86_REG_R8D)
            return 1;
        else
            return 0;
        break;
    case R9D:
        if (detail->x86.operands[0].reg == X86_REG_R9D)
            return 1;
        else
            return 0;
        break;
    default:
        break;
    }

    return 0;
}

int build_code_profile(handle_t *h)
{
    csh disas_handle;
    cs_insn *insn;
    cs_detail *detail;

    // int mode = h->arch == 32 ? CS_MODE_32 : CS_MODE_64;
    ElfW(Off) offset = h->elf.entry - h->elf.textVaddr;
    uint8_t *code = &h->elf.mem[offset];

    unsigned long target_address, callsite;
    char *tmp;
    int c, argc;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disas_handle) != CS_ERR_OK) {
        printf("ERROR: Failed to initialize engine!\n");
        return -1;
    }

    cs_option(disas_handle, CS_OPT_DETAIL, CS_OPT_ON);

    /*
        ElfW(Addr) dot_text = get_section_address(h, ".text");

        if (dot_text != 0) {
            size_t text_section_size = get_section_size(h, ".text");
            count = cs_disasm_ex(disas_handle, code, text_section_size, dot_text, 0, &insn);
        }
        else
    */

    size_t count = cs_disasm(disas_handle, code, h->elf.textSize, h->elf.entry, 0, &insn);

    if (count < 1) {
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
        return -1;
    }

    for (size_t j = 0; j < count; j++) {
        // Is the instruction a type of jmp?
        if (cs_insn_group(disas_handle, &insn[j], CS_GRP_JUMP)) {
            detail = insn[j].detail;
            if (detail->x86.operands[0].type == X86_OP_IMM) {
                // Found a non-call branch instruction
                h->branch_site[h->branch_count].branch_type = IMMEDIATE_JMP;
                h->branch_site[h->branch_count].branch.location = callsite = insn[j].address;
                h->branch_site[h->branch_count].branch.target_vaddr = target_address = detail->x86.operands[0].imm;
                h->branch_site[h->branch_count].branch.target_offset = target_address - callsite - 1;
                h->branch_site[h->branch_count].branch.mnemonic = cs_insn_name(disas_handle, insn[j].id);

                if (opts.debug)
                    printf("[+] Storing information for instruction: jmp %lx\n", target_address);

                h->branch_count++;
                continue;
            }
        }

        // Is the instruction a call?
        if (insn[j].id == X86_INS_CALL) {
            detail = insn[j].detail;
            // Which type of call?
            if (detail->x86.operands[0].type == X86_OP_IMM) {
                h->branch_site[h->branch_count].branch_type = IMMEDIATE_CALL;
                h->branch_site[h->branch_count].branch.location = callsite = insn[j].address;
                h->branch_site[h->branch_count].branch.target_vaddr = target_address = detail->x86.operands[0].imm;
                h->branch_site[h->branch_count].branch.target_offset = target_address - callsite - sizeof(uint32_t);
                h->branch_site[h->branch_count].branch.ret_target = insn[j + 1].address;
                h->branch_site[h->branch_count].branch.mnemonic = cs_insn_name(disas_handle, insn[j].id);

                if ((tmp = get_fn_name(h, target_address)) != NULL)
                    h->branch_site[h->branch_count].branch.function = xstrdup(tmp);
                else
                    tmp = h->branch_site[h->branch_count].branch.function =
                        xfmtstrdup("sub_%lx", target_address);

                if (fn_is_local(h, tmp))
                    h->branch_site[h->branch_count].branch.calltype = LOCAL_CALL;
                else
                    h->branch_site[h->branch_count].branch.calltype = PLT_CALL;

                for (argc = 0, c = 0; c < MAX_ARGS; c++) {
                    switch (c) {
                    case 0:
                        argc += check_for_reg(insn[j - (c + 1)], EDI);
                        break;
                    case 1:
                        argc += check_for_reg(insn[j - (c + 1)], ESI);
                        break;
                    case 2:
                        argc += check_for_reg(insn[j - (c + 1)], EDX);
                        break;
                    case 3:
                        argc += check_for_reg(insn[j - (c + 1)], ECX);
                        break;
                    case 4:
                        argc += check_for_reg(insn[j - (c + 1)], R8D);
                        break;
                    case 5:
                        argc += check_for_reg(insn[j - (c + 1)], R9D);
                        break;
                    }
                }
                /*
                 * We search to see if the same function has been called before, and if so
                 * is the argument count larger than what we just found? If so then use that
                 * argc value because it is likely correct over the one we just found (Which may
                 * be thrown off due to gcc optimizations
                 */

                h->branch_site[h->branch_count].branch.argc = argc;

                for (c = 0; c < h->branch_count; c++) {
                    if (h->branch_site[c].branch_type != IMMEDIATE_CALL)
                        continue;
                    if (!strcmp(h->branch_site[c].branch.function,
                                h->branch_site[h->branch_count].branch.function))
                        if (h->branch_site[c].branch.argc > argc)
                            h->branch_site[h->branch_count].branch.argc =
                                h->branch_site[c].branch.argc;
                }

                int r;
                bool found_edi = false;
                bool found_esi = false;
                bool found_edx = false;
                bool found_ecx = false;
                bool found_r8 = false;
                //bool found_r9 = false;

                if (argc == 0) {
                    // Try aggressive arg resolution
                    for (c = 0; c < MAX_ARGS + 4; c++) {
                        argc += r = check_for_reg(insn[j - (c + 1)], EDI);
                        if (r != 0) {
                            found_edi = true;
                            break;
                        }
                    }
                    if (found_edi) {
                        for (c = 0; c < MAX_ARGS + 4; c++) {
                            argc += r = check_for_reg(insn[j - (c + 1)], ESI);
                            if (r != 0) {
                                found_esi = true;
                                break;
                            }
                        }
                    }

                    if (found_esi) {
                        for (c = 0; c < MAX_ARGS + 4; c++) {
                            argc += r = check_for_reg(insn[j - (c + 1)], EDX);
                            if (r != 0) {
                                found_edx = true;
                                break;
                            }
                        }
                    }

                    if (found_edx) {
                        for (c = 0; c < MAX_ARGS + 4; c++) {
                            argc += r = check_for_reg(insn[j - (c + 1)], ECX);
                            if (r != 0) {
                                found_ecx = true;
                                break;
                            }
                        }
                    }
                    if (found_ecx) {
                        for (c = 0; c < MAX_ARGS + 4; c++) {
                            argc += r = check_for_reg(insn[j - (c + 1)], R8D);
                            if (r != 0) {
                                found_r8 = true;
                                break;
                            }
                        }
                    }
                    if (found_r8) {
                        for (c = 0; c < MAX_ARGS + 4; c++) {
                            argc += r = check_for_reg(insn[j - (c + 2)], R9D);
                            if (r != 0) {
                                //found_r9 = true;
                                break;
                            }
                        }
                    }
                    h->branch_site[h->branch_count].branch.argc = argc;
                }

                h->branch_count++;
                continue;
            } // else { not yet supported }
        }
    }

    cs_free(insn, count);
    cs_close(&disas_handle);

    return 0;
}
