#ifndef _LZ_H
#define _LZ_H

#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <malloc.h>

/* lightzone.h begin */
#define LIGHTZONE_MINOR			182
#define LZ_ENTRY		_IOR(LIGHTZONE_MINOR, 0x01, lzconf_t)
#define LZ_ALLOC		_IOR(LIGHTZONE_MINOR, 0x02, int)
#define LZ_FREE			_IOW(LIGHTZONE_MINOR, 0x03, int)
#define LZ_MPROTECT		_IOWR(LIGHTZONE_MINOR, 0x04, lzmprot_t)
#define LZ_SET_GLZ		_IOWR(LIGHTZONE_MINOR, 0x05, lzglz_t)

#define CALL_GATE_START_EL1		0xffff800000010000UL
#define CALL_GATE_CODE_LEN		128

#define LZ_PROT_NOSAN			(1 << 0)
#define LZ_PROT_READ			(1 << 1)
#define LZ_PROT_WRITE			(1 << 2)
#define LZ_PROT_EXEC			(1 << 3)
#define LZ_PROT_UNPROT			(1 << 4)

typedef struct {
	unsigned long user_vbar;
	unsigned long ttbr0_tab_start;
	unsigned long ttbr0_tab_end;
	unsigned long call_gate_start;
	unsigned long call_gate_end;
	unsigned long per_gate_start;
	unsigned long per_gate_end;
	bool scalable;
} lzconf_t;

typedef struct {
	unsigned long addr;
	size_t len;
	int zoneid;
	int rc;
} lzmprot_t;

typedef struct {
	int zoneid;
	int gateid;
	int rc;
} lzglz_t;
/* lightzone.h end */

int lz_enter(bool scalable);
int lz_alloc(void);
int lz_free(int zoneid);
int lz_mprotect(unsigned long addr, size_t len, int zoneid, int perm);
int lz_set_glz(int zoneid, int gateid);

void lz_switch_to_unsafe(int zoneid);

/* For both fast and scalable */
#define lz_switch_to_norm()\
	asm volatile (\
		"msr pan, #1"\
		::: "memory"\
	)

/* For scalable */
#define lz_switch_to_gate(gateid)\
	asm volatile (\
		".align 4\n\t"\
		"mov x1, #0xffff80000001ffff\n\t"\
		"movk x1, #0x0\n\t"\
		"mov x0, #" #gateid "\n\t"\
		"blr x1"\
		::: "x0", "x1", "x9", "x10", "x11", "x12", "x30", "memory"\
	)

/* For fast */
#define lz_switch_to_prot()\
	asm volatile (\
		"msr pan, #0"\
		::: "memory"\
	)

#endif
