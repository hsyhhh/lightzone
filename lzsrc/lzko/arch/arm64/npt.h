#ifndef __ARM64_NPT_H__
#define __ARM64_NPT_H__

#include "lightzone.h"

/*
 * The pf handler, mmu notifier, and kernel mem should 
 * consider the order of both levels of page tables.
 * These are some basic operations and notifiers and we
 * will show the correct calling chain.
 * 
 * clear_flush_young:
 *	  The original pte/pmd's AF is cleared and flushed before.
 * However, the HVA to HPA page mapping is still there. Since the
 * AF bit is synced in 1st and 2nd stage MMU, we only check the bit
 * and clear it in stage 2 page table entry for efficiency. That is,
 * only the access and dirty bits in 2nd stage count.
 * 
 * clear_young:
 *	  The calling is the same with clear_flush_young.
 * 
 * test_young:
 *	  The calling is the same with clear_flush_young.
 * 
 * change_pte:
 *	  This is called before the pte is actually set and the original
 * map is cleared so we cannot know the original physical address (IPA)
 * from the process page table. Luckily, the pxxp_clear_flush_notify
 * is always called before. Hence, we do nothing in this callback.
 * 
 * invalidate_range_start:
 *	  This is called before the invalidation.
 * 
 * invalidate_range_end:
 *	  Do nothing.
 * 
 * invalidate_range:
 *	  The original pte/pmd's mapping is cleared and flushed before. So, search
 * the 1st stage page table and clear_flush the entries. Then, clear and flush
 * (may set dirty page) the 2nd stage MMU as well. If there are double mapping,
 * later stage 2 pf will handle this.
 */
#include "lightzone.h"

#define MMU_STAGE1 (1)
#define MMU_STAGE2 (2)

#define ARMV8_PHYS_SHIFT				((u32)48)

#define LZ_PTE_LEAF_ATTR_LO_S2_AF		BIT(10)
#define LZ_PTE_LEAF_ATTR_LO_S1_AF		BIT(10)
#define LZ_PTE_LEAF_ATTR_LO_S2_S2AP_R	BIT(6)
#define LZ_PTE_LEAF_ATTR_LO_S2_S2AP_W	BIT(7)
#define LZ_PTE_LEAF_ATTR_HI_S2_XN		BIT(54)
#define LZ_PTE_LEAF_ATTR_HI_SW			GENMASK(58, 55)
/* SW defined attribute start */
#define LZ_PTE_LEAF_ATTR_LO_S1_PFN		BIT(55)
#define LZ_PTE_LEAF_ATTR_LO_S2_PFN		BIT(55)
/* SW defined attribute end */
#define LZ_PTE_LEAF_ATTR_LO_S2_SH		GENMASK(9, 8)
#define LZ_PTE_LEAF_ATTR_LO_S2_SH_IS	3
#define LZ_PTE_VALID					BIT(0)
#define LZ_PTE_ADDR_MASK				GENMASK(47, PAGE_SHIFT)
#define LZ_TABLE_BIT					(1 << 1)

#define LZ_PTE_TABLE_ATTR_Lx_S2			(LZ_TABLE_BIT | LZ_PTE_VALID)	
#define LZ_PTE_LEAF_ATTR_L0_S2_MEM		(LZ_PTE_LEAF_ATTR_LO_S2_S2AP_R | PTE_S2_MEMATTR(MT_S2_NORMAL) | LZ_PTE_VALID | LZ_TABLE_BIT |\
										LZ_PTE_LEAF_ATTR_LO_S2_AF | FIELD_PREP(LZ_PTE_LEAF_ATTR_LO_S2_SH, LZ_PTE_LEAF_ATTR_LO_S2_SH_IS))
#define LZ_PTE_LEAF_ATTR_L0_S2_DEV		(LZ_PTE_LEAF_ATTR_LO_S2_S2AP_R | PTE_S2_MEMATTR(MT_S2_DEVICE_nGnRE) | LZ_PTE_VALID |\
										LZ_PTE_LEAF_ATTR_HI_S2_XN | LZ_PTE_LEAF_ATTR_LO_S2_AF | LZ_TABLE_BIT |\
										FIELD_PREP(LZ_PTE_LEAF_ATTR_LO_S2_SH, LZ_PTE_LEAF_ATTR_LO_S2_SH_IS))

/* PTE-level op are named after npt_xxx, PGT-level xxx_nested_pgtable. */
int walk_nested_pgtable(pgd_t *npgd, unsigned long ipa, int start_level,
					int level, lz_walk_pt_ops_t *ops, pte_t **ppnpte);
int lz_set_ipa_limit(void);
int lz_setup_stage2(lzproc_t *lzproc);
int lz_init_stage2_mmu_locked(lzproc_t *lzproc);
int lz_register_notifier(lzproc_t *lzproc);
void lz_free_stages(lzproc_t *lzproc);
int lz_user_mem_abort(lzcpu_t *lzcpu, unsigned long addr, int stage);
int lz_kernel_mem_abort(lzcpu_t *lzcpu, unsigned long ipa);
int npt_inv_ipa(lzproc_t *lzproc, pgd_t *s2_pgd_base, unsigned long ipa);
void destroy_nested_pgtable(lzproc_t *lzproc, pgd_t *npgd, u32 ia_bits, u32 start_level, bool free_pgd);
int handle_nested_page_fault(lzproc_t *lzproc, pgd_t *pgt, unsigned long ipa, unsigned long hpa,
			int level, unsigned long flags);
unsigned long add_hva_offset(unsigned long hva, lzproc_t *lzproc);
void stage2_notifier_change_pte(struct mmu_notifier *subscription,
			   struct mm_struct *mm, unsigned long address, pte_t pte);
int stage2_notifier_invalidate_range_start(struct mmu_notifier *subscription,
			   const struct mmu_notifier_range *range);
void stage2_notifier_invalidate_range_end(struct mmu_notifier *subscription,
			   const struct mmu_notifier_range *range);
void stage2_notifier_invalidate_range(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end);
void lz_gate_tab_destroy(lzproc_t *proc);

#endif