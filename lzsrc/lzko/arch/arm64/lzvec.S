#include <linux/arm-smccc.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/mmu.h>

#include "hwdefs.h"

	.text

lz_el1_sync:
	/*
	 * These are copied from KVM. We do not want
	 * user process to access SMC now. However, in the
	 * future version, this can be configured (HCR_EL2.TSC)
	 * from the thread entry. Hence, we never want the
	 * LightZone module to deal with this for code simplicity.
	 */
	adr_this_cpu x1, lz_guest_ctxt, x0
	ldr x1, [x1]
	mov	x0, #ARM_EXCEPTION_TRAP
	b	lz_vm_exit

lz_el2_hyp_fault:
	adr_this_cpu x1, lz_guest_ctxt, x0
	ldr x1, [x1]
	mov	x0, #ARM_EXCEPTION_IL
	b	lz_vm_exit

lz_el1_irq:
lz_el1_fiq:
	adr_this_cpu x1, lz_guest_ctxt, x0
	ldr x1, [x1]
	mov	x0, #ARM_EXCEPTION_IRQ
	b	lz_vm_exit

lz_el1_error:
	adr_this_cpu x1, lz_guest_ctxt, x0
	ldr x1, [x1]
	mov	x0, #ARM_EXCEPTION_EL1_SERROR
	b	lz_vm_exit

lz_panic:
	b	lz_vm_exit_panic

.macro valid_vect target
	.align 7
	esb
	stp	x0, x1, [sp, #-16]!
	b	\target
.endm

.macro invalid_vect target
	.align 7
	nop
	stp	x0, x1, [sp, #-16]!
	b	\target
.endm

.align 11
SYM_CODE_START(lz_hyp_vector)
	invalid_vect	lz_panic		// Synchronous EL2t
	invalid_vect	lz_panic		// IRQ EL2t
	invalid_vect	lz_panic		// FIQ EL2t
	invalid_vect	lz_panic		// Error EL2t

	valid_vect		lz_el2_hyp_fault// Synchronous EL2h
	invalid_vect	lz_panic		// IRQ EL2h
	invalid_vect	lz_panic		// FIQ EL2h
	valid_vect		lz_el2_hyp_fault// Error EL2h

	valid_vect		lz_el1_sync		// Synchronous 64-bit EL1
	valid_vect		lz_el1_irq		// IRQ 64-bit EL1
	valid_vect		lz_el1_fiq		// FIQ 64-bit EL1
	valid_vect		lz_el1_error	// Error 64-bit EL1

	valid_vect		lz_el1_sync		// Synchronous 32-bit EL1
	valid_vect		lz_el1_irq		// IRQ 32-bit EL1
	valid_vect		lz_el1_fiq		// FIQ 32-bit EL1
	valid_vect		lz_el1_error	// Error 32-bit EL1
SYM_CODE_END(lz_hyp_vector)
