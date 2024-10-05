#include <linux/kernel.h>
#include "lightzone.h"
#include "sanitize.h"

static inline bool check_one_inst(unsigned int *p, bool flag) {
	unsigned int inst = *p;
	unsigned short field_highest = inst >> 21; // extract the highest 11 bits
	char field_op0, field_op1, field_CRn, field_CRm, field_op2;
	switch (field_highest)
	{
	case FIELD_HIGHEST_HVC: // hvc
		if((inst & FIELD_ID_HVC_MASK) == FIELD_ID_HVC) {
			if(flag) return true;
			else
				return false;
		}
		break;
	case FIELD_HIGHEST_SYS(0):
	case FIELD_HIGHEST_SYS(1):	// system instructions
		field_op0 = (inst >> 19) & 0b11;
		switch (field_op0)
		{
		case 0b00:
			field_CRn = (inst >> 12) & 0b1111;
			field_CRm = (inst >> 8) & 0b1111;
			if(field_CRn == 0b0100) {
				// identify MSR PAN
				field_op2 = (inst >> 5) & 0b111;
				if(field_op2 == 0b100) {
					if(flag || field_CRm == 0b0001) return true; // include 'msr pan, #1'
					else
						return false;
				} else
					return false;
			}
			break;
		case 0b01:
			field_op1 = (inst >> 16) & 0b111;
			field_CRn = (inst >> 12) & 0b1111;
			field_CRm = (inst >> 8) & 0b1111;
			// identify address translation instructions accessible from EL1 or higher
			if(field_CRn == 0b0111 && field_op1 == 0 && (field_CRm == 8 || field_CRm == 9))
				return false;
			break;
		case 0b11:
			field_op1 = (inst >> 16) & 0b111;
			field_CRn = (inst >> 12) & 0b1111;
			field_CRm = (inst >> 8) & 0b1111;
			field_op2 = (inst >> 5) & 0b111;
			if(field_CRn == 0b0100) { // accessing special purpose registers
				// NZCV and FPCR/FPSR are safe
				if(field_op1 == 0b011 && field_CRn == 0b0100 && 
					((field_CRm == 0b0010 && field_op2 == 0b000) || (field_CRm == 0b0100 && field_op2 == 0b000) || (field_CRm == 0b0100 && field_op2 == 0b001))) {
					return true;
				} else {
					// identify PAN
					if(field_op1 == 0b000 && field_CRn == 0b0100 && field_CRm == 0b0010 && field_op2 == 0b011) {
						if(flag) return true;
						else
							return false;
					} else
						return false;
				}
			} else { // accessing non-debug system registers
				if(field_op1 == 0b011) {
					return true;
				} else {
					// identify ttbr0_el1
					if(field_op1 == 0b000 && field_CRn == 0b0010 && field_CRm == 0b0000 && field_op2 == 0b000) {
						if(flag) return true;
						else
							return false;
					} else if(field_op1 == 0b000 && field_CRn == 0b0000 && field_CRm == 0b0000 && field_op2 == 0b000) {
						// mrs x0, midr_el1, emulated in Linux
						/* printk(KERN_ERR "check_one_inst: 0b11, midr_el1, emulated in Linux\n"); */
						return true;
					} else
						return false;
				}
			}
			break;
		case 0b10:	// accessing debug and trace system registers
			field_op1 = (inst >> 16) & 0b111;
			if(field_op1 != 0b011)
				return false;
			break;
		}
		break;
	/* default:
		 if((inst & LOAD_STORE_UNPRI_MASK) == LOAD_STORE_UNPRI_ID)
			return false; */
	}
	return true;
}

/*
 * len: number of instructions
 * flag: true - hvc, eret, pan, ttbr0 is safe
 * return: true - safe, false - unsafe
 */
int inspect(int len, unsigned int *ptr, unsigned long flags, unsigned long hva, lzproc_t *proc) {
	int i;
	unsigned int *cur;

	/* scan each instruction */
	for (i = 0; i < len; i++) {
		cur = ptr + i;

		/* sensitive instruction restriction */
		if (!check_one_inst(cur, flags & LZ_PF_IGNSCAN)) {
			printk(KERN_ERR "lightzone: Bin sanitize failed due to %x\n", *cur);
			return -EINVAL;
		}

		/* code pattern of lz_switch_to_gate */
		if (*cur == GATE_INST_0 && (proc->hcr & HCR_VM) && i + 3 < len)
			if (*(cur + 1) == GATE_INST_1 && (*(cur + 2) & 0xffe0001f) == GATE_MASKED_INST_2 && *(cur + 3) == GATE_INST_3) {
				int gateid = ((*(cur + 2)) >> 5) & 0xffff;
				unsigned long retaddr = (unsigned long)(cur + 4) - (unsigned long)ptr;

				switch (len * sizeof(unsigned int)) {
					case PAGE_SIZE: hva &= PAGE_MASK; break;
					case PTRS_PER_PTE * PAGE_SIZE: hva &= PMD_MASK; break;
					case PTRS_PER_PTE * PTRS_PER_PTE * PAGE_SIZE: hva &= PUD_MASK; break;
					default: hva &= P4D_MASK;
				}
				retaddr += hva;

				if (lz_bind_call_site(proc, gateid, retaddr))
					return -EIO;
			}
	}

	return 0;
}