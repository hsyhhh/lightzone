#ifndef __ARM64_PT_H__
#define __ARM64_PT_H__

#include "lightzone.h"

/* *********** Linux source code begin ************** */
int linux_pud_huge(pud_t pud);
int linux_pmd_huge(pmd_t pmd);
/* ************* Linux source code end ************** */
int walk_pgtable(pgd_t *pgd, unsigned long va, int level, lz_walk_pt_ops_t *ops,
				 pte_t **pppte, spinlock_t **ptlp, unsigned long cont_pgd);
int pt_inv_page(lzproc_t *lzproc, unsigned long va, int *exit_lev);
void destroy_pgtable(lzproc_t *lzproc, pgd_t *pgd, pgd_t *s2_pgd_base);
int get_user_pages_handle_fault(lzcpu_t *lzcpu, pgd_t *lzpgd, unsigned long hva, 
	unsigned long *seqpa, unsigned long *ipa, unsigned long flags, u64 asid);
int lz_init_stage1_mmu(lzproc_t *lzproc, u64 asid, unsigned long *ttbr0);
void lz_free_stage1_mmu(lzproc_t *lzproc, u64 asid);
int pt_op_young(lzproc_t *lzproc, unsigned long va, bool clear);
int pt_clear_pte(lzproc_t *lzproc, pte_t *pte);

#endif