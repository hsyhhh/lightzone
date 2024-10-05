#include "nohammer.h"

static inline unsigned long *seq_pgd_offset_pgd(unsigned long *pgd, unsigned long idx)
{
	return pgd + ((idx & IPA_PGD_MASK) >> PGDIR_SHIFT);
}

static inline unsigned long *seq_pud_offset(unsigned long *pgd, unsigned long idx)
{
	return (unsigned long *)(*pgd) + ((idx & IPA_PUD_MASK) >> PUD_SHIFT);
}

static inline unsigned long *seq_pmd_offset(unsigned long *pud, unsigned long idx)
{
	return (unsigned long *)(*pud) + ((idx & IPA_PMD_MASK) >> PMD_SHIFT);
}

static inline unsigned long *seq_pte_offset(unsigned long *pmd, unsigned long idx)
{
	return (unsigned long *)(*pmd) + ((idx & IPA_PTE_MASK) >> PAGE_SHIFT);
}

static int lz_alloc_next_level(unsigned long *ptr)
{
	void *next_level;
	
	next_level = (void *) __get_free_page(__GFP_HIGH | __GFP_ATOMIC);
	if (!next_level)
		return -ENOMEM;
	memset(next_level, 0, PAGE_SIZE);
	WRITE_ONCE(*ptr, (unsigned long)next_level);
	dsb(ishst);
	isb();

	return 0;
}

static int walk_seqtable(unsigned long *pgd, unsigned long idx, int sl, unsigned long **ptep)
{
	unsigned long *pud;
	unsigned long *pmd;
	unsigned long *pte;

	*ptep = NULL;
	if (sl)
		pud = pgd + (((idx) >> PUD_SHIFT) & ((PTRS_PER_PTE << 1) - 1));
	else {
		pgd = seq_pgd_offset_pgd(pgd, idx);
		if (!(*pgd) && lz_alloc_next_level(pgd))
			return -EINVAL;
		pud = seq_pud_offset(pgd, idx);
	}

	if (!(*pud) && lz_alloc_next_level(pud))
		return -EINVAL;
	pmd = seq_pmd_offset(pud, idx);
	if (!(*pmd) && lz_alloc_next_level(pmd))
		return -EINVAL;
	pte = seq_pte_offset(pmd, idx);

	*ptep = pte;
	if (!(*pte & SEQ_PTE_VALID))
		return 0;
	return 1;
}

int lz_init_seqtable_locked(lzproc_t *lzproc)
{
	size_t pgd_sz;
	void *seq_pgd;
	u64 vtcr = lzproc->vtcr;
	u32 ia_bits = VTCR_EL2_IPA(vtcr);
	u32 sl0 = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	u32 start_level = VTCR_EL2_TGRAN_SL0_BASE - sl0;
	u64 shift = ARM64_HW_PGTABLE_LEVEL_SHIFT(start_level - 1);

	if (!(lzproc->hcr & HCR_VM))
		return 0;

	if (lzproc->counters.seqtable_base) {
		spin_unlock(&lzproc->proc_lock);
		return -EINVAL;
	}
	pgd_sz = ((((-1ULL) & (BIT(ia_bits) - 1)) >> shift) + 1) * PAGE_SIZE;
	seq_pgd = alloc_pages_exact(pgd_sz, __GFP_HIGH | __GFP_ATOMIC | __GFP_ZERO);
	if (!seq_pgd) {
		spin_unlock(&lzproc->proc_lock);
		return -ENOMEM;
	}
	memset(seq_pgd, 0, pgd_sz);
	lzproc->counters.seqtable_base = (unsigned long *)seq_pgd;

	lzproc->counters.pte_aligned_cnt = IPA_PTE_INC;
	lzproc->counters.pmd_aligned_cnt = IPA_PMD_INC;
	lzproc->counters.pud_aligned_cnt = IPA_PUD_INC;

	return 0;
}

unsigned long pa_to_seq(unsigned long pa, lzproc_t *lzproc, int *ret, int level)
{
	int rc, sl, ia_bits;
	unsigned long seq;
	unsigned long *seq_pte;

	ia_bits = VTCR_EL2_IPA(lzproc->vtcr);
	sl = lzproc->start_level;
	rc = walk_seqtable(lzproc->counters.seqtable_base, pa, sl, &seq_pte);

	if (ret)
		*ret = 0;
	else if (rc > 0)
		return (*seq_pte & (~SEQ_PTE_VALID));
	else
		return 0;

	if (rc > 0)
		seq = (*seq_pte & (~SEQ_PTE_VALID));
	else if (rc == 0) {
		if (!(pa & IPA_PMD_MASK)) {
			seq = lzproc->counters.pud_aligned_cnt;
			lzproc->counters.pud_aligned_cnt += IPA_PUD_INC;
		} else if (!(pa & IPA_PTE_MASK)) {
			if (!(lzproc->counters.pmd_aligned_cnt & IPA_PMD_MASK))
				lzproc->counters.pmd_aligned_cnt += IPA_PMD_INC;
			seq = lzproc->counters.pmd_aligned_cnt;
			lzproc->counters.pmd_aligned_cnt += IPA_PMD_INC;
		} else {
			if (!(lzproc->counters.pte_aligned_cnt & IPA_PMD_MASK) ||
				!(lzproc->counters.pte_aligned_cnt & IPA_PTE_MASK))
				lzproc->counters.pte_aligned_cnt += IPA_PTE_INC;
			seq = lzproc->counters.pte_aligned_cnt;
			lzproc->counters.pte_aligned_cnt += IPA_PTE_INC;
		}
		if (seq >= (SEQ_PMD_BASE << (ia_bits - 4)))
			*ret = -EINVAL;
		else
			WRITE_ONCE(*seq_pte, seq | SEQ_PTE_VALID);
	} else
		*ret = -ENOMEM;

	if (level == 1)
		seq += (SEQ_PMD_BASE << (ia_bits - 4));
	else if (level == 2)
		seq += (SEQ_PUD_BASE << (ia_bits - 4));

	return seq;
}

bool check_pa_to_seq(unsigned long pa, lzproc_t *lzproc, unsigned long seq, int guest_lev)
{
	int rc, sl, ia_bits;
	bool is_correct;
	unsigned long *seq_pte;
	unsigned long huge_pmd_lb, huge_pud_lb;

	ia_bits = VTCR_EL2_IPA(lzproc->vtcr);
	huge_pmd_lb = SEQ_PMD_BASE << (ia_bits - 4);
	huge_pud_lb = SEQ_PUD_BASE << (ia_bits - 4);

	/* Range check */
	switch (guest_lev) {
		case 0: is_correct = (seq < huge_pmd_lb); break;
		case 1:
				is_correct = (seq < huge_pud_lb && seq >= huge_pmd_lb);
				seq -= huge_pmd_lb;
				seq &= PMD_MASK;
				pa &= PMD_MASK;
				break;
		case 2:
				is_correct = (seq >= huge_pud_lb);
				seq -= huge_pud_lb;
				seq &= PUD_MASK;
				pa &= PUD_MASK;
				break;
		default: is_correct = false;
	}
	if (!is_correct)
		return false;

	/* Alignment check */
	if (!(pa & IPA_PMD_MASK))
		is_correct = !(seq & ~PUD_MASK);
	else if (!(pa & IPA_PTE_MASK))
		is_correct = !(seq & ~PMD_MASK) && (seq & ~PUD_MASK);
	else
		is_correct = seq & ~PMD_MASK;
	if (!is_correct)
		return false;

	sl = lzproc->start_level;
	rc = walk_seqtable(lzproc->counters.seqtable_base, pa, sl, &seq_pte);

	if (rc > 0)
		return (*seq_pte & (~SEQ_PTE_VALID)) == seq;
	else if (rc == 0) {
		WRITE_ONCE(*seq_pte, seq | SEQ_PTE_VALID);
		return true;
	} else
		return false;
}

inline static void destroy_seq_pmd(unsigned long *pud)
{
	int idx;
	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		unsigned long *pmd = (unsigned long *)(*pud) + idx;
		if (!(*pmd))
			continue;
		free_page((unsigned long)*pmd);
	}
	free_page((unsigned long)*pud);
}

inline static void destroy_seq_pud(unsigned long *pgd)
{
	int idx;
	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		unsigned long *pud = (unsigned long *)(*pgd) + idx;
		if(!(*pud))
			continue;
		destroy_seq_pmd(pud);
	}
	free_page((unsigned long)*pgd);
}

void lz_destroy_seq_table(lzproc_t *lzproc)
{
	size_t pgd_sz;
	int idx, sl;
	unsigned long *pgd;
	unsigned long *seq_pgd = lzproc->counters.seqtable_base;

	if (!seq_pgd)
		return;

	pgd_sz = ((((-1ULL) & (BIT(lzproc->ia_bits) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(lzproc->start_level - 1)) + 1) * PAGE_SIZE;
	sl = lzproc->start_level;

	for (idx = 0; idx < (pgd_sz / PAGE_SIZE) * PTRS_PER_PTE; idx++) {
		pgd = (unsigned long *) (seq_pgd + idx);
		if(!(*pgd))
			continue;
		if (sl) {
			destroy_seq_pmd(pgd);
		} else {
			destroy_seq_pud(pgd);
		}
	}
	free_pages_exact(seq_pgd, pgd_sz);
}