#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>

#include "hwdefs.h"

/* These should be pre-generated include files, the same layout as pt_regs */
#define CPU_XREG_OFFSET(x)		(0 + 8*x)
#define CPU_SP_EL0_OFFSET		(248)
	.text

/*
 * u64 lz_vm_entry(struct pt_regs *regs);
 */
SYM_FUNC_START(lz_vm_entry)
	// x0: ptr_regs
	// x1-x17: clobbered by macros
	// x29: ptr_regs (dup)

	adr_this_cpu x1, lz_host_ctxt, x2

	// Store the callee-saved regs
	str	x18,      [x1, #CPU_XREG_OFFSET(18)]
	stp	x19, x20, [x1, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [x1, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [x1, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [x1, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [x1, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [x1, #CPU_XREG_OFFSET(29)]

	// Save host's sp_el0
	mrs	x2,	sp_el0
	str	x2,	[x1, #CPU_SP_EL0_OFFSET]

	adr_this_cpu x1, lz_guest_ctxt, x2
	str	x0, [x1]

    // Now x29 stores the pt_regs pointer
	mov	x29, x0

	// Restore guest regs
	ldp	x0, x1,   [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x29, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9,   [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]
	ldr	x18,      [x29, #CPU_XREG_OFFSET(18)]
	ldp	x19, x20, [x29, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [x29, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [x29, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [x29, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [x29, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [x29, #CPU_XREG_OFFSET(29)]

	// Do not touch any register after this!
#ifdef RUN_ON_VHE_HOST
	eret
#else
	hvc #1
#endif
	sb

SYM_INNER_LABEL(lz_vm_exit_panic, SYM_L_GLOBAL)
	// x2-x29,lr: vcpu regs
	// vcpu x0-x1 on the stack

	// The host context is saved so make sure it is restored to allow
	// panic to run at hyp and, subsequently, panic to run in the host.
	// This makes use of lz_vm_exit to avoid duplication but sets the
	// return address to tail call into lz_vm_exit_panic_c. As a side
    // effect, the current state is saved to the guest context but it
	// will only be accurate if the guest had been completely restored.
	adr_this_cpu x0, lz_host_ctxt, x1
	adr_l	x1, lz_vm_exit_panic_c
	str	x1, [x0, #CPU_XREG_OFFSET(30)]
	adr_this_cpu x1, lz_guest_ctxt, x0
    ldr x1, [x1]

SYM_INNER_LABEL(lz_vm_exit, SYM_L_GLOBAL)
	// x0: return code
	// x1: ptr_regs
	// x2-x29,lr: vcpu regs
	// ptr_regs x0-x1 on the stack

#ifdef CONFIG_ARM64_PAN
	ALTERNATIVE(nop, SET_PSTATE_PAN(1), ARM64_HAS_PAN)
#else
	SET_PSTATE_PAN(0)
#endif

	// Store the guest regs x2 and x3
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]

	// Retrieve the guest regs x0-x1 from the stack
	ldp	x2, x3, [sp], #16	// x0, x1

	// Store the guest regs x0-x1 and x4-x17
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x1, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x1, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x1, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x1, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x1, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x1, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x1, #CPU_XREG_OFFSET(16)]

	// Store the guest regs x18-x29, lr
	str	x18,      [x1, #CPU_XREG_OFFSET(18)]
	stp	x19, x20, [x1, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [x1, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [x1, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [x1, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [x1, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [x1, #CPU_XREG_OFFSET(29)]

	adr_this_cpu x2, lz_host_ctxt, x3

	// Restore host's sp_el0
    ldr	x3,	  [x2, #CPU_SP_EL0_OFFSET]
	msr	sp_el0, x3

	// Now restore the host regs
	ldr	x18,      [x2, #CPU_XREG_OFFSET(18)]
	ldp	x19, x20, [x2, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [x2, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [x2, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [x2, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [x2, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [x2, #CPU_XREG_OFFSET(29)]
	ret
SYM_FUNC_END(lz_vm_entry)
