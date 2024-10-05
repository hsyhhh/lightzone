/**
 * npt.c - Identical stage 2 mapping.
 *
 * Authors:
 *   Ziqi Yuan   <yuanzqss@zju.edu.cn>
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/mm.h>
#include <linux/bitfield.h>
#include <linux/hugetlb.h>
#include <asm/sysreg.h>
#include <asm/processor.h>
#include <asm/page-def.h>
#include <asm/pgtable-types.h>
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_arm.h>
#include "npt.h"
#include "pt.h"
#include "paravirt.h"
#include "lzarm.h"
#include "sanitize.h"
#include "nohammer.h"

static u32 lz_ipa_limit;
extern char *all_per_vcpu_pages;

static lzpgt_t *ttbr0_to_lzpgt(lzcpu_t *lzcpu)
{
	struct list_head *pos;
	lzpgt_t *tmp;
	u64 asid = (lzcpu->ttbr0 & TTBR_ASID_MASK) >> USER_ASID_BIT;
	unsigned long paddr = lzcpu->ttbr0 & (~TTBR_ASID_MASK);

	list_for_each(pos, &lzcpu->proc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (tmp->s1_asid == asid)
			return (tmp->s1_pgd_seq == paddr) ? tmp : NULL;
	}
	return NULL;
}

void lz_gate_tab_destroy(lzproc_t *proc)
{
	int i = 0;
	int nr = (proc->per_gate_end - proc->per_gate_start) / PAGE_SIZE;

	if (proc->per_gate_pages) {
		for (; i < nr; i++)
			if (proc->per_gate_pages[i])
				put_page(proc->per_gate_pages[i]);
		kfree(proc->per_gate_pages);
		proc->per_gate_pages = NULL;
	}
}

#ifndef ID_AA64MMFR0_PARANGE_SHIFT
#define ID_AA64MMFR0_PARANGE_SHIFT	ID_AA64MMFR0_EL1_PARANGE_SHIFT
#endif
#ifndef ID_AA64MMFR0_PARANGE_48
#define ID_AA64MMFR0_PARANGE_48		(0x5)
#endif
#ifndef ID_AA64MMFR0_TGRAN4_SHIFT
#define ID_AA64MMFR0_TGRAN4_SHIFT	ID_AA64MMFR0_EL1_TGRAN4_SHIFT
#endif
#ifndef ID_AA64MMFR0_PARANGE_MAX
#define ID_AA64MMFR0_PARANGE_MAX	ID_AA64MMFR0_EL1_PARANGE_MAX
#endif
#ifndef ID_AA64MMFR0_TGRAN4_SUPPORTED
#define ID_AA64MMFR0_TGRAN4_SUPPORTED	(0)
#endif

int lz_set_ipa_limit(void)
{
	unsigned int parange;
	u64 mmfr0;

	mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_PARANGE_SHIFT);
	if (PAGE_SIZE != SZ_64K)
		parange = min(parange, (unsigned int)ID_AA64MMFR0_PARANGE_48);

	if (cpuid_feature_extract_unsigned_field(mmfr0, ID_AA64MMFR0_TGRAN4_SHIFT) == ID_AA64MMFR0_TGRAN4_SUPPORTED)
		printk(KERN_INFO "lightzone: PAGE_SIZE 4KB supported at Stage-2 (default)\n");
	else {
		printk(KERN_ERR "lightzone: PAGE_SIZE 4KB not supported at Stage-2, giving up\n");
		return -EINVAL;
	}

	lz_ipa_limit = id_aa64mmfr0_parange_to_phys_shift(parange);
	/* 
	 * The maximum size that can be configured is the same as the physical
	 * address size that is supported by the processor. This is a great feature
	 * that simplifies the stage2 identical mapping.
	 */
	printk(KERN_INFO "lightzone: IPA Size Limit: %d bits%s\n", lz_ipa_limit,
		 ((lz_ipa_limit < ARMV8_PHYS_SHIFT) ?
		  " (Reduced IPA size, limited VM/VMM compatibility)" : ""));

	return 0;
}

int lz_setup_stage2(lzproc_t *lzproc)
{
	unsigned long mmfr0, mmfr1;
	u64 vtcr, parange;
	u8 lvls;

	if (!(lzproc->hcr & HCR_VM))
		return 0;

	mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	mmfr1 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR1_EL1);

	parange = cpuid_feature_extract_unsigned_field(mmfr0,
				ID_AA64MMFR0_PARANGE_SHIFT);
	if (parange > ID_AA64MMFR0_PARANGE_MAX)
		parange = ID_AA64MMFR0_PARANGE_MAX;
	vtcr = VTCR_EL2_FLAGS;	/* VTCR_EL2_RES1 by KVM */
	vtcr |= parange << VTCR_EL2_PS_SHIFT;
	vtcr |= VTCR_EL2_T0SZ(lz_ipa_limit);
	lvls = stage2_pgtable_levels(lz_ipa_limit);
	if (lvls < 2)
		lvls = 2;
	vtcr |= VTCR_EL2_LVLS_TO_SL0(lvls);

	/* MMU manages Access, and software Dirty in stage 2. */
	vtcr |= VTCR_EL2_HA;
	vtcr |= (get_vmid_bits(mmfr1) == 16) ?
		VTCR_EL2_VS_16BIT :
		VTCR_EL2_VS_8BIT;
	lzproc->vtcr = (unsigned long)vtcr;

	return 0;
}

int lz_init_stage2_mmu_locked(lzproc_t *lzproc)
{
	size_t pgd_sz;
	void *s2_pgd;
	u64 vtcr = lzproc->vtcr;
	u32 ia_bits = VTCR_EL2_IPA(vtcr);
	u32 sl0 = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	u32 start_level = VTCR_EL2_TGRAN_SL0_BASE - sl0;
	u64 shift = ARM64_HW_PGTABLE_LEVEL_SHIFT(start_level - 1);

	if (!(lzproc->hcr & HCR_VM))
		return 0;

	if (lzproc->s2_pgd_phys) {
		spin_unlock(&lzproc->proc_lock);
		return -EINVAL;
	}
	pgd_sz = ((((-1ULL) & (BIT(ia_bits) - 1)) >> shift) + 1) * PAGE_SIZE;
	s2_pgd = alloc_pages_exact(pgd_sz, __GFP_HIGH | __GFP_ATOMIC | __GFP_ZERO);
	if (!s2_pgd) {
		spin_unlock(&lzproc->proc_lock);
		return -ENOMEM;
	}
	lzproc->s2_pgd_phys = __pa(s2_pgd);
	lzproc->start_level = start_level;
	lzproc->vttbr = 0;
	lzproc->ia_bits = ia_bits;
	dsb(ishst);

	return 0;
}

static int lz_alloc_pud_ops(pgd_t *pgd, unsigned long data)
{
	void *pud;
	if (!pte_present(__pte(pgd_val(*pgd)))) {
		pud = (void *) __get_free_page(__GFP_HIGH | __GFP_ATOMIC);
		if (!pud)
			return -ENOMEM;
		memset(pud, 0, PAGE_SIZE);
		WRITE_ONCE(*pgd, __pgd(__phys_to_pgd_val(__pa(pud)) | LZ_PTE_TABLE_ATTR_Lx_S2));
		dsb(ishst);
		isb();
	}
	return 0;
}

static int lz_alloc_pmd_ops(pud_t *pud, unsigned long data)
{
	void *pmd;
	if (!pud_present(*pud)) {
		pmd = (void *) __get_free_page(__GFP_HIGH | __GFP_ATOMIC);
		if (!pmd)
			return -ENOMEM;
		memset(pmd, 0, PAGE_SIZE);
		WRITE_ONCE(*pud, __pud(__phys_to_pud_val(__pa(pmd)) | LZ_PTE_TABLE_ATTR_Lx_S2));
		dsb(ishst);
		isb();
	}
	return 0;
}

static int lz_alloc_pte_ops(pmd_t *pmd, unsigned long data)
{
	void *pte;
	if (!pmd_present(*pmd)) {
		pte = (void *) __get_free_page(__GFP_HIGH | __GFP_ATOMIC);
		if (!pte)
			return -ENOMEM;
		memset(pte, 0, PAGE_SIZE);
		WRITE_ONCE(*pmd, __pmd(__phys_to_pmd_val(__pa(pte)) | LZ_PTE_TABLE_ATTR_Lx_S2));
		dsb(ishst);
		isb();
	}
	return 0;
}

int walk_nested_pgtable(pgd_t *npgd, unsigned long ipa, int start_level,
					int level, lz_walk_pt_ops_t *ops, pte_t **ppnpte)
{
#if !(CONFIG_PGTABLE_LEVELS == 4)
#warning "LightZone currently only support 4 level page tables"
#endif
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int counter = CONFIG_PGTABLE_LEVELS - 1 - start_level;

	*ppnpte = NULL;
	if (start_level)
		pud = (pud_t *)(npgd + (((ipa) >> PUD_SHIFT) & ((PTRS_PER_PTE << 1) - 1)));
	else {
		pgd = pgd_offset_pgd(npgd, ipa);
		if ((counter--) <= level) {
			*ppnpte = (pte_t *)pgd;
			return 3;
		}
		if (ops && ops->pgd_ops && ops->pgd_ops(pgd, ops->data))
			return -EINVAL;
		if (!pte_present(__pte(pgd_val(*pgd))))
			return -ENOENT;
		if (pgd_huge(*pgd)) {
			*ppnpte = (pte_t *)pgd;
			return 3;
		}
		pud = pud_offset((p4d_t *)pgd, ipa);
	}
	if ((counter--) <= level) {
		*ppnpte = (pte_t *)pud;
		return 2;
	}
	if (ops && ops->pud_ops && ops->pud_ops(pud, ops->data))
		return -EINVAL;
	if (!pud_present(*pud))
		return -ENOENT;
	if (linux_pud_huge(*pud) || pud_devmap(*pud)) {	/* huge/dev/level */
		*ppnpte = (pte_t *)pud;
		return 2;
	}
	pmd = pmd_offset(pud, ipa);
	if ((counter--) <= level) {
		*ppnpte = (pte_t *)pmd;
		return 1;
	}
	if (ops && ops->pmd_ops && ops->pmd_ops(pmd, ops->data))
		return -EINVAL;
	if (!pmd_present(*pmd))
		return -ENOENT;
	if (linux_pmd_huge(*pmd) || pmd_devmap(*pmd)) {	/* huge/dev/level */
		*ppnpte = (pte_t *)pmd;
		return 1;
	}
	pte = pte_offset_map(pmd, ipa);
	if ((counter--) <= level) {
		*ppnpte = pte;
		return 0;
	}
	if (!pte_present(*pte) || pte_none(*pte))
		return -ENOENT;
	*ppnpte = pte;
	return 0;
}

static int npt_op_young(lzproc_t *lzproc, unsigned long va, bool clear)
{
	int af;
	int inv;
	pte_t *pnpte, *ppte;
	unsigned long ipa;
	struct list_head *pos;
	lzpgt_t *tmp;
	unsigned long cont_pgd = 0;

	af = ipa = 0;
	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (lzproc->hcr & HCR_VM)
			cont_pgd = (unsigned long)__va(tmp->s1_pgd_phys) + (((((-1ULL) & (BIT(48) - 1)) >> 
				ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
		inv = walk_pgtable(__va(tmp->s1_pgd_phys), va, -1, NULL, &ppte,
				NULL, cont_pgd);
		if (inv >= 0) {	/* Success find the entry. */
			af |= (pte_val(*ppte) & LZ_PTE_LEAF_ATTR_LO_S1_AF);
			switch (inv) {
				case 0: ipa = __pte_to_phys(*ppte); break;
				case 1: ipa = __pmd_to_phys(__pmd(pte_val(*ppte))); break;
				case 2: ipa = __pud_to_phys(__pud(pte_val(*ppte))); break;
				default: ipa = __pgd_to_phys(__pgd(pte_val(*ppte))); break;
			}
			if (clear)
				*ppte = __pte(0);
		}
	}

	if (ipa && (lzproc->hcr & HCR_VM)) {
		inv = walk_nested_pgtable((pgd_t *)(__va(lzproc->s2_pgd_phys)), ipa,
				lzproc->start_level, -1, NULL, &pnpte);
		if (inv >= 0) {
			af |= (pte_val(*pnpte) & LZ_PTE_LEAF_ATTR_LO_S2_AF);
			if (clear)
				*pnpte = __pte(0);
		}
	}

	return af;
}

static int npt_clear_npte(lzproc_t *lzproc, pte_t *npte)
{
	if (!pte_val(*npte))	/* pxd_none */
		return 0;
	*npte = __pte(0);
	return 1;
}

int npt_inv_ipa(lzproc_t *lzproc, pgd_t *s2_pgd_base, unsigned long ipa)
{
	pte_t *pnpte = NULL;
	if (!(lzproc->hcr & HCR_VM))
		return 0;
	if (walk_nested_pgtable(s2_pgd_base, ipa, lzproc->start_level, -1, NULL, &pnpte) < 0)
		return 0;
	return npt_clear_npte(lzproc, pnpte);
}

static int npt_inv_page(lzproc_t *lzproc, unsigned long va, int *exit_lev, lzpage_t *pvp)
{
	pte_t *ppte;
	unsigned long ipa;
	struct list_head *pos;
	lzpgt_t *tmp;
	int level, current_lev, rc;
	unsigned long cont_pgd = 0;

	rc = ipa = 0;
	*exit_lev = 3;
	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (lzproc->hcr & HCR_VM)
			cont_pgd = (unsigned long)__va(tmp->s1_pgd_phys) + (((((-1ULL) & (BIT(48) - 1)) >> 
				ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
		level = walk_pgtable(__va(tmp->s1_pgd_phys), va, -1, NULL, &ppte,
				NULL, cont_pgd);
		if (level >= 0) {
			switch (level) {
				case 0: ipa = __pte_to_phys(*ppte); break;
				case 1: ipa = __pmd_to_phys(__pmd(pte_val(*ppte))); break;
				case 2: ipa = __pud_to_phys(__pud(pte_val(*ppte))); break;
				default: ipa = __pgd_to_phys(__pgd(pte_val(*ppte)));
			}
			rc |= pt_clear_pte(lzproc, ppte);
			current_lev = level;
		} else
			current_lev = -level - 1;

		if (*exit_lev > current_lev)
			*exit_lev = current_lev;
	}

	if (ipa && (lzproc->hcr & HCR_VM))
		rc |= PV_npt_inv_ipa(lzproc, (pgd_t *)(__va(lzproc->s2_pgd_phys)), ipa, pvp, *exit_lev);

	return rc;
}

unsigned long add_hva_offset(unsigned long hva, lzproc_t *lzproc)
{
	if (hva >= lzproc->call_gate_start && hva < lzproc->call_gate_end)
		return CALL_GATE_START_EL1 + (hva - lzproc->call_gate_start);	
	if (hva >= lzproc->ttbr0_tab_start && hva < lzproc->ttbr0_tab_end)
		return TTBR0_TAB_START_EL1 + (hva - lzproc->ttbr0_tab_start);
	if (hva >= lzproc->per_gate_start && hva < lzproc->per_gate_end)
		return PER_GATE_ZONE_RET_START_EL1 + (hva - lzproc->per_gate_start);
	return hva;
}

static int stage2_notifier_clear_flush_young(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	unsigned long ostart = start;

	spin_lock(&lzproc->proc_lock);
	for (; start < end; start += PAGE_SIZE)
		rc |= npt_op_young(lzproc, add_hva_offset(start, lzproc), true);
	if ((lzproc->hcr & HCR_VM) && ostart < lzproc->per_gate_end && end > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	atomic_inc(&lzproc->mn_gen);
	smp_mb();
	if (ostart <= lzproc->vbar && end >= lzproc->vbar) {
		printk(KERN_INFO "lightzone: Clear flush young vbar\n");
		atomic_set(&lzproc->vbar_unmapped, 1);
	}
	spin_unlock(&lzproc->proc_lock);
	if (rc)
		PV_lz_flush_tlb_by_vmid(lzproc, 0, 0);

	return rc;
}

static int stage2_notifier_clear_young(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	unsigned long ostart = start;

	spin_lock(&lzproc->proc_lock);
	for (; start < end; start += PAGE_SIZE)
		rc |= npt_op_young(lzproc, add_hva_offset(start, lzproc), true);
	if ((lzproc->hcr & HCR_VM) && ostart < lzproc->per_gate_end && end > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	atomic_inc(&lzproc->mn_gen);
	smp_mb();
	if (ostart <= lzproc->vbar && end >= lzproc->vbar) {
		printk(KERN_INFO "lightzone: Clear young vbar\n");
		atomic_set(&lzproc->vbar_unmapped, 1);
	}
	spin_unlock(&lzproc->proc_lock);
	return rc;
}

static int stage2_notifier_test_young(struct mmu_notifier *subscription,
			  struct mm_struct *mm, unsigned long address)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	spin_lock(&lzproc->proc_lock);
	rc |= npt_op_young(lzproc, add_hva_offset(address, lzproc), false);
	spin_unlock(&lzproc->proc_lock);
	return rc;
}

void stage2_notifier_change_pte(struct mmu_notifier *subscription,
			   struct mm_struct *mm, unsigned long address, pte_t pte)
{
	int rc, exit_lev;
	lzpage_t *pvp;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);

	spin_lock(&lzproc->proc_lock);
	pvp = get_pv_page_aq();
	rc = npt_inv_page(lzproc, add_hva_offset(address, lzproc), &exit_lev, pvp);
	if ((lzproc->hcr & HCR_VM) && address < lzproc->per_gate_end &&
			(address + PAGE_SIZE) > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	PV_npt_inv_action(lzproc, pvp);
	put_pv_page_rl();
	atomic_inc(&lzproc->mn_gen);
	spin_unlock(&lzproc->proc_lock);
	if (rc)
		PV_lz_flush_tlb_by_vmid(lzproc, 0, 0);
}

int stage2_notifier_invalidate_range_start(struct mmu_notifier *subscription,
			   const struct mmu_notifier_range *range)
{
	/* Since the mmap lock is held, we do not worry about page fault. */
	unsigned long start = range->start;
	int exit_lev;
	lzpage_t *pvp;
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);

	atomic_inc(&lzproc->mn_start_end_balance);
	smp_mb();
	spin_lock(&lzproc->proc_lock);
	pvp = get_pv_page_aq();
	for (; start < range->end;) {
		rc |= npt_inv_page(lzproc, add_hva_offset(start, lzproc), &exit_lev, pvp);
		switch (exit_lev) {
			case 0: start += PAGE_SIZE; break;
			case 1: start += PAGE_SIZE * PTRS_PER_PTE; break;
			case 2: start += PAGE_SIZE * PTRS_PER_PTE * PTRS_PER_PTE; break;
			default: start += PAGE_SIZE * PTRS_PER_PTE * PTRS_PER_PTE * PTRS_PER_PTE;
		}
	}
	if ((lzproc->hcr & HCR_VM) && range->start < lzproc->per_gate_end &&
				range->end > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	PV_npt_inv_action(lzproc, pvp);
	put_pv_page_rl();
	spin_unlock(&lzproc->proc_lock);

	if (rc)
		PV_lz_flush_tlb_by_vmid(lzproc, 0, 0);
	return 0;
}

void stage2_notifier_invalidate_range_end(struct mmu_notifier *subscription,
			   const struct mmu_notifier_range *range)
{
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	atomic_inc(&lzproc->mn_gen);
	smp_mb();
	if (range->start <= lzproc->vbar &&
				range->end >= lzproc->vbar) {
		printk(KERN_INFO "lightzone: Invalidate end vbar\n");
		atomic_set(&lzproc->vbar_unmapped, 1);
	}
	atomic_dec(&lzproc->mn_start_end_balance);
}

void stage2_notifier_invalidate_range(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end) {}

static const struct mmu_notifier_ops lz_npt_mmu_notifier_ops = {
	.clear_flush_young		= stage2_notifier_clear_flush_young,
	.clear_young			= stage2_notifier_clear_young,
	.test_young				= stage2_notifier_test_young,
	.change_pte				= stage2_notifier_change_pte,
	.invalidate_range_start	= stage2_notifier_invalidate_range_start,
	.invalidate_range_end	= stage2_notifier_invalidate_range_end,
	.invalidate_range		= stage2_notifier_invalidate_range,
};

int lz_register_notifier(lzproc_t *lzproc)
{
	lzproc->mn.ops = &lz_npt_mmu_notifier_ops;
	return __mmu_notifier_register(&lzproc->mn, lzproc->host_mm);
}

inline static void destroy_nested_pte(lzproc_t *lzproc, pte_t *npte)
{
	int idx;
	
	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		pte_t *pte = &npte[idx];
		if (!pte_present(*pte))
			continue;
	}
	free_page((unsigned long)npte);
}

inline static void destroy_nested_pmd(lzproc_t *lzproc, pmd_t *npmd)
{
	int idx;

	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		pmd_t *pmd = &npmd[idx];
		if (!pmd_present(*pmd))
			continue;
		if (linux_pmd_huge(*pmd))
			continue;
		if (pmd_devmap(*pmd))
			continue;
		destroy_nested_pte(lzproc, (pte_t *)__va(__pmd_to_phys(*pmd)));	
	}
	free_page((unsigned long)npmd);
}

inline static void destroy_nested_pud(lzproc_t *lzproc, pud_t *npud)
{
	int idx;
	
	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		pud_t *pud = &npud[idx];
		if (!pud_present(*pud))
			continue;
		if (linux_pud_huge(*pud))
			continue;
		if (pud_devmap(*pud))
			continue;
		destroy_nested_pmd(lzproc, (pmd_t *)__va(pud_page_paddr(*pud)));
	}
	free_page((unsigned long)npud);
}

void destroy_nested_pgtable(lzproc_t *lzproc, pgd_t *npgd, u32 ia_bits, u32 start_level, bool free_pgd)
{
	/* This function traverse and destroy the nested page table. */
#if !(CONFIG_PGTABLE_LEVELS == 4)
#warning "LightZone currently only support 4 level page tables"
#endif
	size_t pgd_sz;
	int idx;
	pgd_sz = ((((-1ULL) & (BIT(ia_bits) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(start_level - 1)) + 1) * PAGE_SIZE;

	/* 
	 * Refer to kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt). For
	 * simplicity, we assume the kernel uses 4 levels of page tables. If
	 * LightZone is used in other configs, we can easily manage this.
	 */
	for (idx = 0; idx < (pgd_sz / PAGE_SIZE) * PTRS_PER_PTE; idx++) {
		pgd_t *pgd = &npgd[idx];
		if (!pte_present(__pte(pgd_val(*pgd))))	/* BIT(0) */
			continue;

		if (start_level) {
			if (linux_pud_huge(__pud(pgd_val(*pgd))) || pud_devmap(__pud(pgd_val(*pgd))))
				continue;
			destroy_nested_pmd(lzproc, (pmd_t *)__va(pud_page_paddr(__pud(pgd_val(*pgd)))));
		} else {
			if (pgd_huge(*pgd))
				continue;
			destroy_nested_pud(lzproc, (pud_t *)__va(p4d_page_paddr(__p4d(pgd_val(*pgd)))));
		}
	}
	if (free_pgd)
		free_pages_exact(npgd, pgd_sz);
	else
		memset(npgd, 0, pgd_sz);
}

void lz_free_stages(lzproc_t *lzproc)
{
	struct list_head *pos, *n;
	lzpgt_t *tmp;
	if (lzproc->host_mm)
		mmu_notifier_unregister(&lzproc->mn, lzproc->host_mm);
	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		destroy_pgtable(lzproc, __va(tmp->s1_pgd_phys), __va(0));
		tmp->s1_pgd_phys = 0;
		tmp->s1_pgd_seq = 0;
	}
	list_for_each_safe(pos, n, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		list_del(&tmp->list_s1_mmu);
		kfree(tmp);
	}
	PV_lz_flush_tlb_by_vmid_s1(lzproc, 0);
	
	PV_destroy_nested_pgtable(lzproc, (pgd_t *)(__va(lzproc->s2_pgd_phys)),
			lzproc->ia_bits, lzproc->start_level, true);
	lzproc->s2_pgd_phys = 0;

	if (lzproc->hcr & HCR_VM) {
		PV_lz_flush_tlb_by_vmid(lzproc, 0, 0);
		lz_gate_tab_destroy(lzproc);
		lz_destroy_seq_table(lzproc);
	}
}

int handle_nested_page_fault(lzproc_t *lzproc, pgd_t *pgt, unsigned long ipa, unsigned long hpa,
			int level, unsigned long flags)
{
	int rc;
	pte_t *pnpte;
	unsigned long pte_attr = 0;
	int sl = lzproc->start_level;
	lz_walk_pt_ops_t ops = {
		.pgd_ops = lz_alloc_pud_ops,
		.pud_ops = lz_alloc_pmd_ops,
		.pmd_ops = lz_alloc_pte_ops,
		.data = (unsigned long)lzproc,
	};

	if (level < 0 || level > 3)
		return -EINVAL;

	rc = walk_nested_pgtable(pgt, ipa, sl, level, &ops, &pnpte);
	if (rc < 0)
		return rc;

	if (pte_present(*pnpte)) {
		if (unlikely(rc != level || hpa != (pte_val(*pnpte) & LZ_PTE_ADDR_MASK))) {
			printk(KERN_ERR "lightzone: The kernel should unmap IPA %lx before remap it\n", ipa);
			return -EINVAL;
		}
		if (pud_devmap(*(pud_t *)pnpte) || pmd_devmap(*(pmd_t *)pnpte))
			/* skip device */;
		else if (!sl && level == 3 && !pgd_huge(*(pgd_t *)pnpte))
			destroy_nested_pud(lzproc, (pud_t *)__va(p4d_page_paddr(*(p4d_t *)pnpte)));
		else if (level == 2 && !linux_pud_huge(*(pud_t *)pnpte))
			destroy_nested_pmd(lzproc, (pmd_t *)__va(pud_page_paddr(*(pud_t *)pnpte)));
		else if (level == 1 && !linux_pmd_huge(*(pmd_t *)pnpte))
			destroy_nested_pte(lzproc, (pte_t *)__va(__pmd_to_phys(*(pmd_t *)pnpte)));
		*pnpte = __pte(0);
		PV_lz_flush_tlb_by_vmid(lzproc, level ? 0 : ipa, flags & LZ_PF_IN_GUEST);
	}

	if (flags & LZ_PF_PFNMAP)
		pte_attr |= LZ_PTE_LEAF_ATTR_LO_S2_PFN;
	if (flags & LZ_PF_IO)
		pte_attr |= LZ_PTE_LEAF_ATTR_L0_S2_DEV;
	else
	 	pte_attr |= LZ_PTE_LEAF_ATTR_L0_S2_MEM;
	if (flags & LZ_PF_WRITE)	/* dirty + write */
		pte_attr |= LZ_PTE_LEAF_ATTR_LO_S2_S2AP_W;
	if (level)	/* huge page */
		pte_attr &= (~LZ_TABLE_BIT);

	WRITE_ONCE(*pnpte, __pte((hpa & LZ_PTE_ADDR_MASK) | pte_attr));
	dsb(ishst);
	isb();
	return 0;
}

int lz_user_mem_abort(lzcpu_t *lzcpu, unsigned long addr, int stage)
{
	// lock mmap read, get user pages, 1st pgtable, unlock, stage 2
	unsigned long ipa, seqpa, hva, flags, ttbr1_hva;
	int rc;
	bool wr_fault, i_fault, s1pf;
	struct mm_struct *mm;
	lzpgt_t *pgt;
	u64 esr_el1 = lzcpu->esr_el1;

	flags = LZ_PF_GATE;
	rc = 0;
	seqpa = ipa = addr;
	s1pf = (stage == MMU_STAGE1);
	hva = s1pf ? lzcpu->far_el1 : lzcpu->far;
	ttbr1_hva = hva | LZ_USER_TTBR1_MASK;

	mm = lzcpu->proc->host_mm;
	wr_fault = (s1pf ? esr_el1 : lzcpu->esr) & ESR_ELx_WNR;
	i_fault = s1pf ? (ESR_ELx_EC(esr_el1) == ESR_ELx_EC_IABT_CUR) : false;
	mmap_read_lock(mm);

	if (s1pf && 
		((ttbr1_hva >= lzcpu->proc->ttbr0_tab_start && ttbr1_hva < lzcpu->proc->ttbr0_tab_end) ||
		(ttbr1_hva >= lzcpu->proc->call_gate_start && ttbr1_hva < lzcpu->proc->call_gate_end) ||
		(ttbr1_hva >= lzcpu->proc->per_gate_start && ttbr1_hva < lzcpu->proc->per_gate_end))) {
		printk(KERN_ERR "lightzone: S1 permission fault detected or TTBR conflict\n");
		rc = -EFAULT;
		goto fail_stage1;
	}

	flags |= wr_fault ? LZ_PF_WRITE : 0;
	flags |= i_fault ? LZ_PF_INST : 0;
	flags |= s1pf ? LZ_PF_STAGE1 : 0;
	flags |= (lzcpu->spsr_el1 & PSR_PAN_BIT) ? LZ_PF_PAN : 0;

	if (hva & LZ_USER_TTBR1_MASK) {
		ttbr1_hva = lzcpu->ttbr0;
		lzcpu->ttbr0 = lzcpu->proc->default_ttbr0;
	}
	pgt = ttbr0_to_lzpgt(lzcpu);
	if (hva & LZ_USER_TTBR1_MASK)
		lzcpu->ttbr0 = ttbr1_hva;

	if (pgt)
		rc = get_user_pages_handle_fault(lzcpu, __va(pgt->s1_pgd_phys),
			hva, &seqpa, &ipa, flags, (lzcpu->ttbr0 & TTBR_ASID_MASK) >> USER_ASID_BIT);
	else {
		spin_lock(&lzcpu->proc->proc_lock);
		rc = -EINVAL;
	}

	if (rc < 0) {
		printk(KERN_ERR "lightzone: Failed to handle S1 fault %lx for permission violation [%d]\n", hva, current->pid);
		goto fail_stage1_spin_unlock;
	} else {
		flags |= rc;
		rc = 0;
	}

	/* 
	 * Sync with user's page size, e.g., huge pmd.
	 * For S1 fault, do S1 fault and sync level by level for an address.
	 * For S2, if user is a small page but the NPT gives us a huge page, it will never happen.
	 * If user page is huge, but the NPT entry points to some smaller pages, collapse the small
	 * pages and the PTE, and rebuild the huge page.
	 */
	if (lzcpu->proc->hcr & HCR_VM)
		if ((rc = PV_handle_nested_page_fault(lzcpu->proc, (pgd_t *)(__va(lzcpu->proc->s2_pgd_phys)), seqpa, ipa,
			(flags & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT, flags)))
			printk(KERN_ERR "lightzone: Failed to handle IPA fault\n");

fail_stage1_spin_unlock:
	spin_unlock(&lzcpu->proc->proc_lock);
fail_stage1:
	mmap_read_unlock(mm);

	return rc;
}

static int handle_kernel_npt_fault(lzcpu_t *lzcpu, pgd_t *pgt, unsigned long seqpa, unsigned long ipa)
{
	int rc = 0;

	/*
	 * Stage one page table is a shadow memory that can be written with A, D bits.
	 * Even if the malicious APP write its page table, it cannot corrupt other memory
	 * regions because the satge2 page table only maps s1 tables and its user memory.
	 */
	if (lzcpu->proc->hcr & HCR_VM)
		rc = PV_handle_nested_page_fault((lzcpu->proc), pgt, seqpa, ipa, 0, 0);	/* READ-ONLY */
	if (rc)
		printk(KERN_ERR "lightzone: Failed to handle kernel IPA fault\n");
	return rc;
}

static int lz_match_pud_ops(pgd_t *pgd, unsigned long data)
{
	if (pte_present(__pte(pgd_val(*pgd))) && data == __pgd_to_phys(*pgd))
		return 1;
	return 0;
}

static int lz_match_pmd_ops(pud_t *pud, unsigned long data)
{
	if (pud_present(*pud) && data == __pud_to_phys(*pud))
		return 1;
	return 0;
}

static int lz_match_pte_ops(pmd_t *pmd, unsigned long data)
{
	if (pmd_present(*pmd) && data == __pmd_to_phys(*pmd))
		return 1;
	return 0;
}

int lz_kernel_mem_abort(lzcpu_t *lzcpu, unsigned long ipa)
{
	/* Stage 2, never compound, struct page. */
	struct mm_struct *mm;
	unsigned long pa, pgd_sz, ttbr0;
	pte_t *ppte;
	lzpgt_t *pgt;
	lz_walk_pt_ops_t ops = {
		.data = ipa & PAGE_MASK,
		.pgd_ops = lz_match_pud_ops,
		.pud_ops = lz_match_pmd_ops,
		.pmd_ops = lz_match_pte_ops,
	};
	int rc, fault_level;

	mm = lzcpu->proc->host_mm;
	rc = 0;
	ppte = NULL;
	mmap_read_lock(mm);
	spin_lock(&lzcpu->proc->proc_lock);

	if (lzcpu->far & LZ_USER_TTBR1_MASK) {
		ttbr0 = lzcpu->ttbr0;
		lzcpu->ttbr0 = lzcpu->proc->default_ttbr0;
	}
	pgt = ttbr0_to_lzpgt(lzcpu);
	if (lzcpu->far & LZ_USER_TTBR1_MASK)
		lzcpu->ttbr0 = ttbr0;

	if (pgt) {
		if (lzcpu->proc->hcr & HCR_VM) {
			pgd_sz = ((((-1ULL) & (BIT(48) - 1)) >> 
					ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE;

			if (ipa >= pgt->s1_pgd_seq && ipa < pgt->s1_pgd_seq + pgd_sz)
				pa = (pgt->s1_pgd_phys + (ipa - pgt->s1_pgd_seq)) & PAGE_MASK;
			else {
				fault_level = -walk_pgtable(__va(pgt->s1_pgd_phys), lzcpu->far,
					-1, &ops, &ppte, NULL, (unsigned long)__va(pgt->s1_pgd_phys) + pgd_sz) - 1;
				switch (fault_level) {
					case 1: pa = __pmd_to_phys(*((pmd_t *)((unsigned long)ppte + PAGE_SIZE))); break;
					case 2: pa = __pud_to_phys(*((pud_t *)((unsigned long)ppte + PAGE_SIZE))); break;
					default: pa = __pgd_to_phys(*((pgd_t *)((unsigned long)ppte + pgd_sz)));
				}
			}
		} else
			pa = ipa & PAGE_MASK;	/* For LightZone in VM */

		rc = handle_kernel_npt_fault(lzcpu, (pgd_t *)(__va(lzcpu->proc->s2_pgd_phys)), ipa, pa);
	} else
		rc = -EFAULT;

	spin_unlock(&lzcpu->proc->proc_lock);
	mmap_read_unlock(mm);
	return rc;
}
