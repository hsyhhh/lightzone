#include <sys/syscall.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>

#include "liblz.h"
#include "lz.h"
#include "lzdefs.h"

#define PGSIZE (1u << 12)
#define VECTOR_TABLE_SIZE (1u << 11)

int lz_enter(bool scalable)
{
	int ret, fd;
	lzconf_t conf;
	assert((unsigned long long) __lz_vectors_end -
		   (unsigned long long) __lz_vectors == VECTOR_TABLE_SIZE);
	assert(LZ_TTBR0_TAB_SZ == (1 * PAGE_SIZE));
	assert(LZ_CALL_GATE_SZ == (1 * PAGE_SIZE));
	assert((unsigned long long) __lz_call_gate_end -
		   (unsigned long long) __lz_call_gate == LZ_CALL_GATE_SZ);
	assert(LZ_PER_GATE_SZ == (1 * PAGE_SIZE));
	assert(CALL_GATE_CODE_LEN == 128);
	mlock((unsigned long long)__lz_vectors, (unsigned long long)__lz_vectors_end -
		   (unsigned long long)__lz_vectors);
	conf.user_vbar = (unsigned long long)__lz_vectors;
	conf.ttbr0_tab_start = (unsigned long long)__lz_ttbr0_tab;
	conf.ttbr0_tab_end = (unsigned long long)__lz_ttbr0_tab + LZ_TTBR0_TAB_SZ;
	conf.call_gate_start = (unsigned long long)__lz_call_gate;
	conf.call_gate_end = (unsigned long long)__lz_call_gate + LZ_CALL_GATE_SZ;
	conf.per_gate_start = (unsigned long long)__lz_zone_ret_tab;
	conf.per_gate_end = (unsigned long long)__lz_zone_ret_tab + LZ_PER_GATE_SZ;
	conf.scalable = scalable;
	fd = open("/dev/lightzone", O_RDWR);
	ret = ioctl(fd, LZ_ENTRY, &conf);
	close(fd);
	return ret;
}

int lz_alloc(void)
{
	int fd, zoneid;
	fd = open("/dev/lightzone", O_RDWR);
	if (ioctl(fd, LZ_ALLOC, &zoneid))
		zoneid = -1;
	close(fd);
	return zoneid;
}

int lz_free(int zoneid)
{
	int fd, ret;
	fd = open("/dev/lightzone", O_RDWR);
	ret = ioctl(fd, LZ_FREE, &zoneid);
	close(fd);
	return ret;
}

int lz_mprotect(unsigned long addr, size_t len, int zoneid, int perm)
{
	int ret, fd;
	lzmprot_t mprot;
	mprot.addr = addr;
	mprot.len = len;
	mprot.zoneid = zoneid;
	mprot.rc = perm;
	fd = open("/dev/lightzone", O_RDWR);
	ret = ioctl(fd, LZ_MPROTECT, &mprot);
	close(fd);
	if (!ret)
		ret = mprot.rc;
	return ret;
}

int lz_set_glz(int zoneid, int gateid)
{
	int ret, fd;
	lzglz_t glz;
	glz.zoneid = zoneid;
	glz.gateid = gateid;
	fd = open("/dev/lightzone", O_RDWR);
	ret = ioctl(fd, LZ_SET_GLZ, &glz);
	close(fd);
	return ret;
}

#ifdef LZDEBUG
void lz_switch_to_unsafe(int zoneid)
{
	register unsigned long ttbr0_val;
	if (zoneid < 0) /* enable PAN */
		asm volatile (
			"msr pan, #1\n\t"
			"isb"
			::: "memory"
		);
	else {  /* switch TTBR and disable PAN */
		ttbr0_val = ((unsigned long long *)TTBR0_TAB_START_EL1)[zoneid];
		asm volatile (
			"msr ttbr0_el1, %0\n\t"
			"msr pan, #0\n\t"
			"isb"
			:: "r"(ttbr0_val) : "memory"
		);
	}
}
#endif
