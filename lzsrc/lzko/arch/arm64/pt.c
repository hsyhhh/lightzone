#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <asm/kvm_hyp.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable-prot.h>
#include <asm/syscall.h>
#include "pt.h"
#include "npt.h"
#include "lzarm.h"
#include "copied.h"
#include "paravirt.h"
#include "sanitize.h"
#include "nohammer.h"

extern char *all_per_vcpu_pages;

#ifdef CONFIG_HIGHMEM
#warning "High memory is not supported because of complex huge page binary sanitizer!"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
#define HUGE_PTEP_GET(ptep)		huge_ptep_get(ptep)
#else
#define HUGE_PTEP_GET(ptep)		IMPORTED(huge_ptep_get)(ptep)
#endif

/* *********** Linux source code begin ************** */
int linux_pud_huge(pud_t pud)
{
#ifndef __PAGETABLE_PMD_FOLDED
	return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#else
	return 0;
#endif
}

#define unlock_ptl_lock_proc(hpte, ptl, lzproc)\
{\
	if (*(ptl)) {\
		pte_unmap_unlock((hpte), *(ptl));\
		*(ptl) = NULL;\
	}\
	spin_lock(&(lzproc)->proc_lock);\
	if (atomic_read(&(lzproc)->mn_gen) != mn_gen || atomic_read(&(lzproc)->mn_start_end_balance) > 0) {\
		spin_unlock(&(lzproc)->proc_lock);\
		goto retry_valid_vma;\
	}\
}

int linux_pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}
/* ************* Linux source code end ************** */
/* 
 * Refer to the follow_page function in mm/gup.c. (more than AArch64)
 * Return the walking level.
 */
int walk_pgtable(pgd_t *pgd, unsigned long va,
		int level, lz_walk_pt_ops_t *ops, pte_t **pppte,
		spinlock_t **ptlp, unsigned long cont_pgd)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int counter = CONFIG_PGTABLE_LEVELS - 1;

	*pppte = NULL;

	pgd = pgd_offset_pgd(pgd, va);
	if ((counter--) <= level) {
		*pppte = (pte_t *)pgd;
		return 3;
	}
	if (ops && ops->pgd_ops && ops->pgd_ops(pgd, ops->data)) {
		*pppte = (pte_t *)pgd;
		return -4;
	}
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -4;
	if (pgd_huge(*pgd)) {
		*pppte = (pte_t *)pgd;
		return 3;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -4;
	if (cont_pgd)
		pud = pud_offset(p4d_offset(pgd_offset_pgd((pgd_t *)cont_pgd, va), va), va);
	else
		pud = pud_offset(p4d, va);
	if ((counter--) <= level) {
		*pppte = (pte_t *)pud;
		return 2;
	}
	if (ops && ops->pud_ops && ops->pud_ops(pud, ops->data)) {
		*pppte = (pte_t *)pud;
		return -3;
	}
	if (pud_none(*pud))
		return -3;
	/*
	 * Page migration may happen.
	 * In MMU notifiers, invalidate -> change_pte notifiers comes. We ignore this
	 * case because LightZone stage1 page tables are invalidated before migration.
	 * Thus, if a page is undergoing migration, it is not present and no MMU notifier
	 * synchronization should be done. 
	 */
	if (linux_pud_huge(*pud)) {
		if (pte_present(HUGE_PTEP_GET((pte_t *)pud))) {
			*pppte = (pte_t *)pud;
			return 2;
		} else
			return -3;
	}
	if (pud_devmap(*pud)) {
		*pppte = (pte_t *)pud;
		return 2;
	}
	if (pud_bad(*pud))
		return -3;
	if (cont_pgd)
		pmd = pmd_offset((pud_t *)((unsigned long)pud + PAGE_SIZE), va);
	else
		pmd = pmd_offset(pud, va);
	if ((counter--) <= level) {
		*pppte = (pte_t *)pmd;
		return 1;
	}
	if (ops && ops->pmd_ops && ops->pmd_ops(pmd, ops->data)) {
		*pppte = (pte_t *)pmd;
		return -2;
	}
	if (pmd_none(*pmd))
		return -2;
	if (linux_pmd_huge(*pmd)) {
		if (pte_present(HUGE_PTEP_GET((pte_t *)pmd))) {
			*pppte = (pte_t *)pmd;
			return 1;
		} else
			return -2;
	}
	if (!pmd_present(*pmd))
		return -2;
	if (pmd_devmap(*pmd)) {
		*pppte = (pte_t *)pmd;
		return 1;
	}
	if (likely(!pmd_trans_huge(*pmd))) {
		if (unlikely(pmd_bad(*pmd)))
			return -2;
		if (ptlp)
			pte = pte_offset_map_lock(current->mm, pmd, va, ptlp);
		else {
			if (cont_pgd)
				pte = pte_offset_map((pmd_t *)((unsigned long)pmd + PAGE_SIZE), va);
			else
				pte = pte_offset_map(pmd, va);
		}
		if ((counter--) <= level) {
			*pppte = pte;
			return 0;
		}
		if (!pte_present(*pte) || pte_none(*pte)) {
			if (ptlp) {
				pte_unmap_unlock(pte, *ptlp);
				*ptlp = NULL;
			}
			return -1;
		}
		*pppte = pte;
		return 0;
	}
	*pppte = (pte_t *)pmd;
	return 1;
}

int pt_clear_pte(lzproc_t *lzproc, pte_t *pte)
{
	if (!pte_val(*pte))	/* pxd_none */
		return 0;
	*pte = __pte(0);
	return 1;
}

int pt_inv_page(lzproc_t *lzproc, unsigned long va, int *exit_lev)
{
	struct list_head *pos;
	lzpgt_t *tmp;
	int rc;
	pte_t *ppte;
	int level, current_lev;
	unsigned long cont_pgd = 0;
	
	/* 
	 * From here, the page may be released. Hence, the page should
	 * never be refered to again. Also, when clearing stage1 MMU,
	 * the operations on physical frames are not required.
	 */
	rc = 0;
	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (lzproc->hcr & HCR_VM)
			cont_pgd = (unsigned long)__va(tmp->s1_pgd_phys) + (((((-1ULL) & (BIT(48) - 1)) >> 
				ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
		level = walk_pgtable(__va(tmp->s1_pgd_phys), va, -1, NULL, &ppte,
				NULL, cont_pgd);
		if (level >= 0) {
			rc |= pt_clear_pte(lzproc, ppte);
			current_lev = level;
		} else
			current_lev = -level - 1;

		if (*exit_lev > current_lev)
			*exit_lev = current_lev;
	}

	return rc;
}

static void destroy_pte(lzproc_t *lzproc, pte_t *pte_base, pgd_t *s2_pgd_base, lzpage_t *pvp)
{
	/* 
	 * These 2 operations should be in this order.
	 * Otherwise, there might be another thread with the 
	 * newly freed page set the hash map, but cleared later
	 * by this thread.
	 */
	int rc;
	int sz = PAGE_SIZE;
	unsigned long seqpa = __pa(pte_base);

	if (lzproc->hcr & HCR_VM) {
		seqpa = pa_to_seq(__pa(pte_base), lzproc, &rc, 0);
		sz *= 2;
	}

	if (s2_pgd_base != __va(0))
		PV_npt_inv_ipa(lzproc, s2_pgd_base, seqpa, pvp, 0);

	free_pages_exact(pte_base, sz);
}

static void destroy_pmd(lzproc_t *lzproc, pmd_t *pmd_base, pgd_t *s2_pgd_base, lzpage_t *pvp)
{
	int idx, rc;
	unsigned long pte_va;
	unsigned long seqpa = __pa(pmd_base);
	size_t sz = PAGE_SIZE;

	if (lzproc->hcr & HCR_VM) {
		seqpa = pa_to_seq(__pa(pmd_base), lzproc, &rc, 0);
		sz *= 2;
	}

	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		pmd_t *pmd = &pmd_base[idx];
		if (!pmd_present(*pmd))
			continue;
		if (linux_pmd_huge(*pmd))
			continue;
		if (pmd_devmap(*pmd) || pmd_trans_huge(*pmd))
			continue;
		if (lzproc->hcr & HCR_VM)
			pte_va = (unsigned long)__va(__pmd_to_phys(*(pmd_t *)((unsigned long)pmd + PAGE_SIZE)));
		else
			pte_va = (unsigned long)__va(__pmd_to_phys(*pmd));
		destroy_pte(lzproc, (pte_t *)pte_va, s2_pgd_base, pvp);
	}

	if (s2_pgd_base != __va(0))
		PV_npt_inv_ipa(lzproc, s2_pgd_base, seqpa, pvp, 0);

	free_pages_exact(pmd_base, sz);
}

static void destroy_pud(lzproc_t *lzproc, pud_t *pud_base, pgd_t *s2_pgd_base, lzpage_t *pvp)
{
	int idx, rc;
	unsigned long pmd_va;
	unsigned long seqpa = __pa(pud_base);
	size_t sz = PAGE_SIZE;

	if (lzproc->hcr & HCR_VM) {
		seqpa = pa_to_seq(__pa(pud_base), lzproc, &rc, 0);
		sz *= 2;
	}

	for (idx = 0; idx < PTRS_PER_PTE; idx++) {
		pud_t *pud = &pud_base[idx];
		if (!pud_present(*pud))
			continue;
		if (linux_pud_huge(*pud))
			continue;
		if (pud_devmap(*pud))
			continue;
		if (lzproc->hcr & HCR_VM)
			pmd_va = (unsigned long)__va(pud_page_paddr(*(pud_t *)((unsigned long)pud + PAGE_SIZE)));
		else
			pmd_va = (unsigned long)__va(pud_page_paddr(*pud));
		destroy_pmd(lzproc, (pmd_t *)pmd_va, s2_pgd_base, pvp);
	}

	if (s2_pgd_base != __va(0))
		PV_npt_inv_ipa(lzproc, s2_pgd_base, seqpa, pvp, 0);

	free_pages_exact(pud_base, sz);
}

void destroy_pgtable(lzproc_t *lzproc, pgd_t *pgd_base, pgd_t *s2_pgd_base)
{
#if !(CONFIG_PGTABLE_LEVELS == 4)
#warning "LightZone currently only support 4 level page tables"
#endif
	size_t pgd_sz, sz;
	lzpage_t *pvp;
	unsigned long seqpa, pud_va;
	int idx;
	pgd_sz = ((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE;

	/* 
	 * Refer to kvm_pgtable_stage2_destroy(struct kvm_pgtable *pgt). For
	 * simplicity, we assume the kernel uses 4 levels of page tables. If
	 * LightZone is used in other configs, we can easily manage this. Also,
	 * stage2 page table entries are 4KB for simplicity.
	 */
	pvp = get_pv_page_aq();
	for (idx = 0; idx < (pgd_sz / PAGE_SIZE) * PTRS_PER_PTE; idx++) {
		pgd_t *pgd = &pgd_base[idx];
		if (p4d_none(__p4d(pgd_val(*pgd))))	/* BIT(0) */
			continue;
		if (pgd_huge(*pgd))
			continue;
		if (lzproc->hcr & HCR_VM)
			pud_va = (unsigned long)__va(p4d_page_paddr(*(p4d_t *)((unsigned long)pgd + pgd_sz)));
		else
			pud_va = (unsigned long)__va(p4d_page_paddr(__p4d(pgd_val(*pgd))));
		destroy_pud(lzproc, (pud_t *)pud_va, s2_pgd_base, pvp);
	}

	if (s2_pgd_base != __va(0))
		for (sz = 0; sz < pgd_sz; sz += PAGE_SIZE) {
			if (lzproc->hcr & HCR_VM)
				seqpa = pa_to_seq(__pa(pgd_base) + sz, lzproc, &idx, 0);
			else
				seqpa = __pa(pgd_base) + sz;
			PV_npt_inv_ipa(lzproc, s2_pgd_base, seqpa, pvp, 0);
		}

	put_pv_page_rl();

	if (lzproc->hcr & HCR_VM)
		pgd_sz *= 2;
	free_pages_exact(pgd_base, pgd_sz);
}

/*
 * For table type, NS, AP, XN, PXN, are ignored just like Linux.
 * https://medium.com/@om.nara/arm64-normal-memory-attributes-6086012fa0e3
 */
static int lz_alloc_pud_ops(pgd_t *pgd, unsigned long data)
{
	void *pud;
	unsigned long seqpa;
	int rc;
	size_t sz = PAGE_SIZE, pgd_sz = (((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
	lzproc_t *proc = (lzproc_t *)data;

	if (proc->hcr & HCR_VM)
		sz *= 2;

	if (pgd_none(*pgd) || p4d_none(__p4d(pgd_val(*pgd)))) {
		pud = (void *) alloc_pages_exact(sz, __GFP_HIGH | __GFP_ATOMIC);
		if (!pud)
			return -ENOMEM;
		if (proc->hcr & HCR_VM) {
			seqpa = pa_to_seq(__pa(pud), proc, &rc, 0);
			if (rc) {
				free_pages_exact(pud, sz);
				return rc;
			}
		} else
			seqpa = __pa(pud);
		memset(pud, 0, sz);
		WRITE_ONCE(*pgd, __pgd(__phys_to_pgd_val(seqpa) | LZ_P4D_TYPE_TABLE));
		if (proc->hcr & HCR_VM)
			WRITE_ONCE(*(pgd_t *)((unsigned long)pgd + pgd_sz),
				__pgd(__phys_to_pgd_val(__pa(pud)) | LZ_P4D_TYPE_TABLE));
		dsb(ishst);
		isb();
	}
	return 0;
}

static int lz_alloc_pmd_ops(pud_t *pud, unsigned long data)
{
	void *pmd;
	unsigned long seqpa;
	int rc;
	size_t sz = PAGE_SIZE;
	lzproc_t *proc = (lzproc_t *)data;

	if (proc->hcr & HCR_VM)
		sz *= 2;

	if (pud_none(*pud)) {
		pmd = (void *) alloc_pages_exact(sz, __GFP_HIGH | __GFP_ATOMIC);
		if (!pmd)
			return -ENOMEM;
		if (proc->hcr & HCR_VM) {
			seqpa = pa_to_seq(__pa(pmd), proc, &rc, 0);
			if (rc) {
				free_pages_exact(pmd, sz);
				return rc;
			}
		} else
			seqpa = __pa(pmd);
		memset(pmd, 0, sz);
		WRITE_ONCE(*pud, __pud(__phys_to_pud_val(seqpa) | PUD_TYPE_TABLE));
		if (proc->hcr & HCR_VM)
			WRITE_ONCE(*(pud_t *)((unsigned long)pud + PAGE_SIZE),
				__pud(__phys_to_pud_val(__pa(pmd)) | PUD_TYPE_TABLE));
		dsb(ishst);
		isb();
	}
	return 0;
}

static int lz_alloc_pte_ops(pmd_t *pmd, unsigned long data)
{
	void *pte;
	unsigned long seqpa;
	int rc;
	size_t sz = PAGE_SIZE;
	lzproc_t *proc = (lzproc_t *)data;

	if (proc->hcr & HCR_VM)
		sz *= 2;

	if (pmd_none(*pmd)) {
		pte = (void *) alloc_pages_exact(sz, __GFP_HIGH | __GFP_ATOMIC);
		if (!pte)
			return -ENOMEM;
		if (proc->hcr & HCR_VM) {
			seqpa = pa_to_seq(__pa(pte), proc, &rc, 0);
			if (rc) {
				free_pages_exact(pte, sz);
				return rc;
			}
		} else
			seqpa = __pa(pte);
		memset(pte, 0, sz);
		WRITE_ONCE(*pmd, __pmd(__phys_to_pmd_val(seqpa) | PMD_TYPE_TABLE));
		if (proc->hcr & HCR_VM)
			WRITE_ONCE(*(pmd_t *)((unsigned long)pmd + PAGE_SIZE),
				__pmd(__phys_to_pmd_val(__pa(pte)) | PMD_TYPE_TABLE));
		dsb(ishst);
		isb();
	}
	return 0;
}

static int handle_shadow_page_fault(lzproc_t *lzproc, pgd_t *pgd, pgd_t *s2_pgd, unsigned long hva,
			unsigned long seqpa, int level, pte_t host_pte, int overlay)
{
	int rc;
	pte_t *ppte;
	lzpage_t *pvp;
	lz_walk_pt_ops_t ops = {
		.pgd_ops = lz_alloc_pud_ops,
		.pud_ops = lz_alloc_pmd_ops,
		.pmd_ops = lz_alloc_pte_ops,
		.data = (unsigned long)lzproc,
	};
	unsigned long pxd_va;
	unsigned long cont_pgd = 0, pgd_sz = (((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);

	if (level < 0 || level > 3)
		return -EINVAL;

	if (lzproc->hcr & HCR_VM)
		cont_pgd = (unsigned long)pgd + pgd_sz;
	rc = walk_pgtable(pgd, hva, level, &ops, &ppte, NULL, cont_pgd);
	if (rc < 0)
		return rc;

	if (pte_present(*ppte)) {	/* Permission fault or Access fault */
		pvp = get_pv_page_aq();
		if (pud_devmap(*(pud_t *)ppte) || pmd_devmap(*(pmd_t *)ppte))
			/* skip device */;
		else if (level == 3 && !pgd_huge(*(pgd_t *)ppte)) {
			if (lzproc->hcr & HCR_VM)
				pxd_va = (unsigned long)__va(p4d_page_paddr(*(p4d_t *)((unsigned long)ppte + pgd_sz)));
			else
				pxd_va = (unsigned long)__va(p4d_page_paddr(*(p4d_t *)ppte));
			destroy_pud(lzproc, (pud_t *)pxd_va, s2_pgd, pvp);
		} else if (level == 2 && !linux_pud_huge(*(pud_t *)ppte)) {
			if (lzproc->hcr & HCR_VM)
				pxd_va = (unsigned long)__va(pud_page_paddr(*(pud_t *)((unsigned long)ppte + PAGE_SIZE)));
			else
				pxd_va = (unsigned long)__va(pud_page_paddr(*(pud_t *)ppte));
			destroy_pmd(lzproc, (pmd_t *)pxd_va, s2_pgd, pvp);
		} else if (level == 1 && !linux_pmd_huge(*(pmd_t *)ppte)) {
			if (lzproc->hcr & HCR_VM)
				pxd_va = (unsigned long)__va(__pmd_to_phys(*(pmd_t *)((unsigned long)ppte + PAGE_SIZE)));
			else
				pxd_va = (unsigned long)__va(__pmd_to_phys(*(pmd_t *)ppte));
			destroy_pte(lzproc, (pte_t *)pxd_va, s2_pgd, pvp);
		}
		*ppte = __pte(0);
		if (unlikely(!PV_npt_inv_empty(pvp)))
			PV_npt_inv_action(lzproc, pvp);
		put_pv_page_rl();
		PV_lz_flush_tlb_by_vmid_s1(lzproc, level ? 0 : hva);
	}

	if (lzproc->hcr & HCR_VM)
		host_pte = __pte(((pte_val(host_pte) & (~PTE_ADDR_MASK))) | seqpa);

	/* User page to kernel, other such as MAIR and Global bit are copied. */
	if (overlay & LZ_PROT_UNPROT)
		host_pte = __pte(pte_val(host_pte) & (~PTE_USER));

	if ((pte_val(host_pte) & PTE_UXN) || !(overlay & LZ_PROT_EXEC))
		host_pte = __pte(pte_val(host_pte) | PTE_PXN | PTE_AF);
	else
		host_pte = __pte((pte_val(host_pte) & (~PTE_PXN)) | PTE_AF);
	if (!(overlay & LZ_PROT_WRITE))
		WRITE_ONCE(*ppte, __pte(pte_val(host_pte) | PTE_RDONLY));
	else
		WRITE_ONCE(*ppte, __pte(pte_val(host_pte)));
	dsb(ishst);
	isb();

	return 0;
}

static inline bool not_enough_perm(pte_t *hpte, unsigned long flags)
{
	if (flags & LZ_PF_INST)
		return pte_val(*hpte) & PTE_UXN;
	if (flags & LZ_PF_WRITE)
		return pte_val(*hpte) & PTE_RDONLY;
	return false;
}

noinline static lzrange_t *find_lzrange(unsigned long addr, lzproc_t *proc)
{
	lzrange_t *data;
	struct rb_root *root = &proc->lzrange;
	struct rb_node *node = root->rb_node;

  	while (node) {
  		data = rb_entry(node, lzrange_t, node);
		if (addr < data->start)
  			node = node->rb_left;
		else if (addr >= data->end)
  			node = node->rb_right;
		else
  			return data;
	}

	return NULL;
}

noinline static bool is_unpriv_load_store(u64 elr_hva)
{
	int rc;
	u32 insn;
	u32 highest;
	struct page *page;
	
	rc = get_user_pages(elr_hva & PAGE_MASK, 1, FOLL_FORCE, &page, NULL);
	if (rc != 1)
		return false;
	insn = *((u32 *)(page_to_virt(page) + (elr_hva & ~PAGE_MASK)));
	highest = insn >> 21;
	put_page(page);
	if (highest != FIELD_HIGHEST_HVC && highest != FIELD_HIGHEST_SYS(0) &&
			highest != FIELD_HIGHEST_SYS(1) && (insn & LOAD_STORE_UNPRI_MASK) == LOAD_STORE_UNPRI_ID)
		return true;
	return false;
}

int get_user_pages_handle_fault(lzcpu_t *lzcpu, pgd_t *lzpgd, unsigned long hva, 
			unsigned long *seqpa, unsigned long *ipa, unsigned long flags, u64 asid)
{
	spinlock_t *ptl;
	lzrange_t *range;
	pte_t *hpte;
	pte_t hpte_val;
	u64 extra_prot;
	int rc, zone_idx;
	unsigned long guphva;
	void *start_kaddr;
	int inspect_rc, lev;
	bool attacked, pf_handled;
	int extra_flags, lzprot;
	u32 mn_gen;
	struct vm_area_struct *vma;
	unsigned long fault_flags, vm_flags, mm_flags, pte_ipa, pte_seqpa;
	lzproc_t *lzproc = lzcpu->proc;

	inspect_rc = extra_prot = extra_flags = 0;
	range = NULL;
	ptl = NULL;
	attacked = false;
	guphva = hva;
	if (hva & LZ_USER_TTBR1_MASK) {
		extra_prot = PTE_RDONLY;
		attacked = flags & LZ_PF_WRITE;

		if (hva >= CALL_GATE_START_EL1 && hva < CALL_GATE_START_EL1 +
			(lzproc->call_gate_end - lzproc->call_gate_start))	/* Call gate R-X, GLOBAL */
			guphva = lzproc->call_gate_start + (hva - CALL_GATE_START_EL1);
		else if (hva >= TTBR0_TAB_START_EL1 && hva < TTBR0_TAB_START_EL1 +
			(lzproc->ttbr0_tab_end - lzproc->ttbr0_tab_start)) {	/* RO data R--, GLOBAL */
			guphva = lzproc->ttbr0_tab_start + (hva - TTBR0_TAB_START_EL1);	
			extra_prot |= PTE_UXN;
		} else if (hva >= PER_GATE_ZONE_RET_START_EL1 && hva < PER_GATE_ZONE_RET_START_EL1 +
			(lzproc->per_gate_end - lzproc->per_gate_start)) {
			guphva = lzproc->per_gate_start + (hva - PER_GATE_ZONE_RET_START_EL1);	
			extra_prot |= PTE_UXN;
		}
		/* Otherwise, GUP will return EFAULT. */
	}

retry:
	vma = find_vma(current->mm, guphva);
	if (vma) {
		if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP))
			extra_flags |= LZ_PF_PFNMAP;
		if (vma->vm_flags & VM_IO)
			extra_flags |= LZ_PF_IO;
	} else
		extra_flags = LZ_PF_PFNMAP;

retry_valid_vma:
	pf_handled = false;
	fault_flags = VM_FAULT_ERROR;
	mm_flags = FAULT_FLAG_DEFAULT | FAULT_FLAG_USER;
	vm_flags = VM_ACCESS_FLAGS;

	if (flags & LZ_PF_WRITE) {
		mm_flags |= FAULT_FLAG_WRITE;
		vm_flags |= VM_WRITE;
	} else if (flags & LZ_PF_INST) {
		mm_flags |= FAULT_FLAG_INSTRUCTION;
		vm_flags |= VM_EXEC;
	}

	mn_gen = atomic_read(&lzproc->mn_gen);
	if (vma && !(vma->vm_start > guphva && ((!(vma->vm_flags & VM_GROWSDOWN)) ||
			IMPORTED(expand_stack)(vma, guphva))) && (vma->vm_flags & vm_flags)) {
		fault_flags = handle_mm_fault(vma, guphva & PAGE_MASK, mm_flags, NULL);
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	if (fault_flags & VM_FAULT_COMPLETED) {
		/*
		 * This is copied from fixup_user_fault().
		 * From here, we lock the mmap_lock again.
		 * And later we walk the page table, so the
		 * design is safe.
		 */
		mmap_read_lock(current->mm);
	} else
#endif
	if (fault_flags & VM_FAULT_RETRY) {
		if (mm_flags & FAULT_FLAG_ALLOW_RETRY) {
			mm_flags |= FAULT_FLAG_TRIED;
			mmap_read_lock(current->mm);
			goto retry;
		}
	}

	if (!(fault_flags & VM_FAULT_ERROR))
		pf_handled = true;

	if (pf_handled) {
		rc = walk_pgtable(current->mm->pgd, guphva, -1, NULL, &hpte, &ptl, 0);
		if (rc >= 0)
			hpte_val = __pte(pte_val(*hpte) | extra_prot);
		switch (rc) {
			case 0: pte_ipa = __pte_to_phys(*hpte); break;
			case 1: pte_ipa = __pmd_to_phys(__pmd(pte_val(*hpte))); break;
			case 2: pte_ipa = __pud_to_phys(__pud(pte_val(*hpte))); break;
			case 3: pte_ipa = __pgd_to_phys(__pgd(pte_val(*hpte))); break;
			default: goto retry_valid_vma;
		}

		if (flags & LZ_PF_STAGE1) {
			range = find_lzrange(hva, lzproc);
			zone_idx = 4;
			if (range) {
				for (zone_idx = 0; zone_idx < 4; zone_idx++)
					if (range->zoneid[zone_idx] == asid)
						break;
			}

			if ((flags & LZ_PF_INST) && !(extra_flags & LZ_PF_PFNMAP)) {
				unsigned long sz = PAGE_SIZE;
				start_kaddr = __va(pte_ipa);
				pte_unmap_unlock(hpte, ptl);
				lev = rc;
				if ((hva >= lzproc->vbar && hva < lzproc->vbar + (1UL << 11)) ||
								((hva & LZ_USER_TTBR1_MASK) == LZ_USER_TTBR1_MASK))
					flags |= LZ_PF_IGNSCAN;
				while ((lev--) > 0)
					sz *= PTRS_PER_PTE;
				if (!(lzproc->hcr & HCR_VM))
					flags |= LZ_PF_IGNSCAN;
				if (zone_idx >= 4 || !(range->perm[zone_idx] & LZ_PROT_NOSAN)) {
					inspect_rc = inspect(sz / sizeof(unsigned int), (unsigned int *)start_kaddr, flags, hva, lzproc);
					if (inspect_rc)
						printk(KERN_ERR "lightzone: Failed to pass binary inspection\n");
				}
				spin_lock(ptl);
			}
		}

		lev = rc;
		*ipa = PV_convert_aligned_pa(pte_ipa, hva, lev);
	}

	if (flags & LZ_PF_STAGE1) {
		if ((!pf_handled) || inspect_rc || attacked) {
			unlock_ptl_lock_proc(hpte, &ptl, lzproc);	/* LightZone Permission fault. */
			return -EFAULT;
		}

		if (range && (zone_idx >= 4 || (flags & LZ_PF_PAN))) {
			if (ptl) {
				pte_unmap_unlock(hpte, ptl);
				ptl = NULL;
			}
			if (!is_unpriv_load_store(lzcpu->elr_el1)) {
				spin_lock(&lzproc->proc_lock);
				if (atomic_read(&lzproc->mn_gen) != mn_gen ||
						atomic_read(&lzproc->mn_start_end_balance) > 0) {
					spin_unlock(&lzproc->proc_lock);
					goto retry_valid_vma;
				}
				return -EFAULT;
			}
		}

		lzprot = range ? range->perm[zone_idx] : LZ_PROT_DEF;
		if (!(flags & LZ_PF_INST))
			hpte_val = __pte(pte_val(hpte_val) | PTE_UXN);
		else if (!(lzprot & LZ_PROT_EXEC)) {
			unlock_ptl_lock_proc(hpte, &ptl, lzproc);
			return -EFAULT;
		}
		if ((flags & LZ_PF_WRITE) && !(lzprot & LZ_PROT_WRITE)) {
			unlock_ptl_lock_proc(hpte, &ptl, lzproc);
			return -EFAULT;
		}
		if (extra_prot || !range)
			hpte_val = __pte(pte_val(hpte_val) & (~PTE_NG));
		else
			hpte_val = __pte(pte_val(hpte_val) | PTE_NG);
		if (extra_flags & LZ_PF_PFNMAP)
			hpte_val = __pte(pte_val(hpte_val) | LZ_PTE_LEAF_ATTR_LO_S1_PFN);
		else
			hpte_val = __pte(pte_val(hpte_val) & (~LZ_PTE_LEAF_ATTR_LO_S1_PFN));
		unlock_ptl_lock_proc(hpte, &ptl, lzproc);
		if (!(pte_val(hpte_val) & PTE_RDONLY))
			extra_flags |= LZ_PF_WRITE;
		if (lzproc->hcr & HCR_VM) {
			pte_seqpa = pa_to_seq(pte_ipa, lzproc, &rc, lev);
			if (rc)
				return -EFAULT;
		} else
			pte_seqpa = pte_ipa;
		if (handle_shadow_page_fault(lzproc, lzpgd, (pgd_t *)__va(lzproc->s2_pgd_phys),
				hva, pte_seqpa, lev, hpte_val, lzprot))
			return -EFAULT;
	} else {
		unlock_ptl_lock_proc(hpte, &ptl, lzproc);
		if (!pf_handled)
			return -EFAULT;
		if (lzproc->hcr & HCR_VM) {
			pte_seqpa = pa_to_seq(pte_ipa, lzproc, &rc, lev);
			if (rc)
				return -EFAULT;
		} else
			pte_seqpa = pte_ipa;
	}

	WRITE_ONCE(*seqpa, PV_convert_aligned_pa(pte_seqpa, hva, lev));
	extra_flags |= lev << LZ_PF_LEV_SHIFT;
	return extra_flags;
}

int lz_init_stage1_mmu(lzproc_t *lzproc, u64 asid, unsigned long *ttbr0)
{
	lzpgt_t *s1pgt;
	pgd_t *pgd_base;
	int rc;
	unsigned long ipa, seqpa, cont_pgd;
	pte_t *ppte;
	size_t pgd_sz;
	lzcpu_t *tmp = kzalloc(sizeof(lzcpu_t), GFP_KERNEL);

	if (!tmp)
		return -EINVAL;
	tmp->proc = lzproc;

	pgd_sz = ((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE;
	if (lzproc->hcr & HCR_VM)
		pgd_sz *= 2;

	rc = 0;
	mmap_assert_write_locked(lzproc->host_mm);

	/* The library is found, now map it (exception handler). */
	s1pgt = kzalloc(sizeof(lzpgt_t), GFP_KERNEL);
	if (!s1pgt) {
		rc = -ENOMEM;
		goto fail_init_s1;
	}
	INIT_LIST_HEAD(&s1pgt->list_s1_mmu);
	pgd_base = (pgd_t *)alloc_pages_exact(pgd_sz, __GFP_HIGH | __GFP_ATOMIC | __GFP_ZERO);
	if (!pgd_base) {
		rc = -ENOMEM;
		goto free_s1pgt;
	}

	if (lzproc->hcr & HCR_VM) {
		s1pgt->s1_pgd_seq = pa_to_seq(__pa(pgd_base), lzproc, &rc, 0);
		if (rc) {
			s1pgt->s1_pgd_seq = 0;
			goto destroy_table;
		}
		cont_pgd = (unsigned long)pgd_base + (((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
	} else {
		s1pgt->s1_pgd_seq = __pa(pgd_base);
		cont_pgd = 0;
	}

	s1pgt->s1_pgd_phys = __pa(pgd_base);
	s1pgt->s1_asid = asid;

	if (walk_pgtable(pgd_base, lzproc->vbar, -1, NULL, &ppte, NULL, cont_pgd) < 0) {
		/* The address is not mapped in S1 page table yet. */
		rc = get_user_pages_handle_fault(tmp, pgd_base, lzproc->vbar, &seqpa, &ipa, LZ_PF_INIT, 0);
		if (rc >= 0 && (lzproc->hcr & HCR_VM))
			if ((rc = PV_handle_nested_page_fault(lzproc, (pgd_t *)(__va(lzproc->s2_pgd_phys)), seqpa, ipa,
				(rc & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT, LZ_PF_INIT | rc)))
				printk(KERN_ERR "lightzone: Failed to handle IPA fault\n");
		spin_unlock(&lzproc->proc_lock);
		if (rc < 0)
			goto destroy_table;
	}

	list_add(&s1pgt->list_s1_mmu, &lzproc->list_s1_mmu);	/* Protected by mmap_write_lock */
	if (!asid)
		lzproc->default_ttbr0 = s1pgt->s1_pgd_seq;
	rc = 0;
	goto fail_init_s1;

destroy_table:
	destroy_pgtable(lzproc, pgd_base, (pgd_t *)__va(lzproc->s2_pgd_phys));
free_s1pgt:
	kfree(s1pgt);
fail_init_s1:
	if (!rc && ttbr0)
		*ttbr0 = (s1pgt->s1_pgd_seq | (s1pgt->s1_asid << USER_ASID_BIT));
	kfree(tmp);
	return rc;
}

void lz_free_stage1_mmu(lzproc_t *lzproc, u64 asid)
{
	struct list_head *pos, *n;
	lzpgt_t *tmp;

	/*
	 * lz_free_stage1_mmu must free S2 MMU, too. Otherwise, it doesn't
	 * free the stage-2 MMU (unlike the callbacks of MMU notifiers). 
	 * If the physical memory of S1 pgts is used later for others,
	 * it may become a side channel to leak some secret from address
	 * translation. Hence, defend in-depth is wise.
	 */

	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (tmp->s1_asid == asid) {
			destroy_pgtable(lzproc, (pgd_t *)__va(tmp->s1_pgd_phys),
				(pgd_t *)__va(lzproc->s2_pgd_phys));
			tmp->s1_pgd_phys = 0;
			tmp->s1_pgd_seq = 0;
			break;
		}
	}
	list_for_each_safe(pos, n, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (tmp->s1_asid == asid) {
			list_del(&tmp->list_s1_mmu);
			kfree(tmp);
			break;
		}
	}
	PV_lz_flush_tlb_by_vmid_s1(lzproc, 0);
}

int pt_op_young(lzproc_t *lzproc, unsigned long va, bool clear)
{
	int af;
	int inv;
	pte_t *ppte;
	struct list_head *pos;
	lzpgt_t *tmp;
	unsigned long cont_pgd = 0;

	af = 0;
	list_for_each(pos, &lzproc->list_s1_mmu) {
		tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
		if (lzproc->hcr & HCR_VM)
		cont_pgd = (unsigned long)__va(tmp->s1_pgd_phys) +
			(((((-1ULL) & (BIT(48) - 1)) >> 
			ARM64_HW_PGTABLE_LEVEL_SHIFT(-1)) + 1) * PAGE_SIZE);
		inv = walk_pgtable(__va(tmp->s1_pgd_phys), va, -1,
			NULL, &ppte, NULL, cont_pgd);
		if (inv >= 0) {	/* Success find the entry. */
			af |= (pte_val(*ppte) & LZ_PTE_LEAF_ATTR_LO_S1_AF);
			if (clear)
				*ppte = __pte(0);
		}
	}

	return af;
}
