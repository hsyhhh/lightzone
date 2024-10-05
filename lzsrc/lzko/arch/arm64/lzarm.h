#ifndef __ARM64_LZARM_H__
#define __ARM64_LZARM_H__

#include "lightzone.h"

int lz_arch_init_check(void);
int lz_entry(lzconf_t *lzconf, int from, lzconf_el1_sys_t *lzconf_el1_sys);
void lz_flush_tlb_by_vmid(lzproc_t *lzproc, unsigned long ipa, bool in_guest);
void lz_flush_tlb_by_vmid_s1(lzproc_t *lzproc, unsigned long gva);

#endif