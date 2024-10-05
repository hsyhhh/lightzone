#ifndef __ARM64_NO_HAMMER_H__
#define __ARM64_NO_HAMMER_H__

#include "lightzone.h"

#define SEQ_PTE_VALID		(0x8000000000000000ULL)
#define SEQ_PMD_BASE		(0x8UL)
#define SEQ_PUD_BASE		(0xCUL)

unsigned long pa_to_seq(unsigned long pa, lzproc_t *lzproc, int *ret, int level);
bool check_pa_to_seq(unsigned long pa, lzproc_t *lzproc, unsigned long seq, int guest_lev);
void lz_destroy_seq_table(lzproc_t *lzproc);
int lz_init_seqtable_locked(lzproc_t *lzproc);

#endif