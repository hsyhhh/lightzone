#include "lzdefs.h"

/*
 * System Call ABI: svc #0
 * ---------------
 *
 * User Parameters:
 * x8 - system call number
 * x0 - return value
 * 
 * Arguments:
 * x0 - arg0, x1 - arg1, x2 - arg2
 * x3 - arg3, x4 - arg4, x5 - arg5
 *
 */

.macro valid_vect
.align 7
.Lventry_start\@:
	hvc #0
	wfe
.org .Lventry_start\@ + 128
.endm

.macro invalid_vect, num
.align 7
.Lventry_start\@:
	hvc #\num
	wfe
.org .Lventry_start\@ + 128
.endm

.text

/* VBAR_EL1:
	0x000	Current EL with SP0
	0x200	Current EL with SPx		<-	call svc in EL1
	0x400	Lower EL using AArch64	<- 	call svc in EL0
	0x600	Lower EL using AArch32
*/
.align 12
.globl	__lz_vectors
__lz_vectors:
	invalid_vect 1		// Synchronous EL1t
	invalid_vect 2		// IRQ EL1t
	invalid_vect 3		// FIQ EL1t
	invalid_vect 4		// Error EL1t

	valid_vect			// Synchronous EL1h
	invalid_vect 6		// IRQ EL1h
	invalid_vect 7		// FIQ EL1h
	invalid_vect 8		// Error EL1h

	invalid_vect 9		// Synchronous 64-bit EL0
	invalid_vect 10		// IRQ 64-bit EL0
	invalid_vect 11		// FIQ 64-bit EL0
	invalid_vect 12		// Error 64-bit EL0

	invalid_vect 13		// Synchronous 32-bit EL0
	invalid_vect 14		// IRQ 32-bit EL0
	invalid_vect 15		// FIQ 32-bit EL0
	invalid_vect 16		// Error 32-bit EL0

.globl __lz_vectors_end
__lz_vectors_end:

.align 12
.global __lz_call_gate	// offset = gateid << 4
__lz_call_gate:
	// the gateid is passed by x0
	// x9 x10 x11 x12 are caller-saved
	// (s64 zoneid, u64 expected_ret)
	msr pan, #0
	cmp	x0, #0x0	// x0 should be in [0, 255]
	blt .Lviolation
	cmp	x0, #0xff
	bgt .Lviolation
	mov x12, #0x4
	mov	x10, #PER_GATE_ZONE_RET_START_LP
	movk x10, #PER_GATE_ZONE_RET_START_HP, lsl #48	// Load base addr of per-gate (zoneid, ret) in x10
	lsl x12, x0, x12
	add x10, x10, x12
	ldr x10, [x10]		// If zoneid == -1. fault will be reised
	mov x12, #0x3
	mov x9, #TTBR0_TAB_START_EL1
	lsl x10, x10, x12
	add x9, x9, x10
	ldr x9, [x9]
	msr ttbr0_el1, x9
	cmp	x0, #0x0
	blt .Lviolation
	cmp	x0, #0xff
	bgt .Lviolation
	mov x12, #0x4
	mov	x10, #PER_GATE_ZONE_RET_START_LP
	movk x10, #PER_GATE_ZONE_RET_START_HP, lsl #48
	lsl x12, x0, x12
	add x10, x10, x12
	ldr x11, [x10, #8]
	ldr x10, [x10]
	mov x12, #0x3
	lsl x10, x10, x12
	mov x12, #TTBR0_TAB_START_EL1
	add x12, x12, x10
	ldr x12, [x12]
	cmp x9, x12
	bne .Lviolation
#ifndef LZDEBUG
	cmp lr, x11
	bne .Lviolation
#endif
	isb		/* For NVIDIA Carmel */
	ret
.Lviolation:
	wfi
.align 12
.globl __lz_call_gate_end
__lz_call_gate_end:

.data

/* RO-shard page of ZONEID->TTBR0, 4KB aligned
*/
.align 12
.globl	__lz_ttbr0_tab
__lz_ttbr0_tab:
.rept PAGE_SIZE
.byte 0x0
.endr

.align 12
.global __lz_zone_ret_tab
__lz_zone_ret_tab:
.rept (PAGE_SIZE / 8 / 2)
.byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
.endr
