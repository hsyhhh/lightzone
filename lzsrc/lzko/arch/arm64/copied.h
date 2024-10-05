#ifndef __ARM64_LZCOPIED_H__
#define __ARM64_LZCOPIED_H__

#include "lzsym.h"

struct tlb_inv_context {
	unsigned long	flags;
	u64		tcr;
	u64		sctlr;
};

/* Copy some hard-to-import static symbols in .c and .h */
void copied_resume_user_mode_work(struct pt_regs *regs);
void copied___tlb_switch_to_host(struct tlb_inv_context *cxt, u64 hcr, u64 vttbr);
void copied___tlb_switch_to_guest(struct tlb_inv_context *cxt, lzproc_t *lzproc);
void copied_do_signal(struct pt_regs *regs, lzcpu_t *lzcpu);

#endif