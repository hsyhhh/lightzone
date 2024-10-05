#include "lightzone.h"
#include "pt.h"
#include "npt.h"
#include "paravirt.h"

#ifndef RUN_ON_VHE_HOST

static bool vcpu_pages_registered = false;
char *all_per_vcpu_pages = NULL;

static int lowvisor_call(unsigned long func_id, unsigned long a0, unsigned long a1, unsigned long a2)
{
	unsigned long ret;

	asm volatile (
		"mov x0, %1\n\t"
		"mov x1, %2\n\t"
		"mov x2, %3\n\t"
		"mov x3, %4\n\t"
		"hvc #0\n\t"
		"mov %0, x0"
		: "=r" (ret) : "r" (func_id), "r" (a0), "r" (a1), "r" (a2) : "x0", "x1", "x2", "x3", "memory");

	return ret;
}

static void smp_share_vcpu_page(void *info)
{
	int rc;
	lzpage_t *pvp;
	int *ret = (int *)info;
	int cpu = get_cpu();

	if (vcpu_pages_registered) {
		free_page((unsigned long)(&all_per_vcpu_pages[cpu * PAGE_SIZE]));
		put_cpu();
		return;
	}
	
	pvp = (lzpage_t *)(&all_per_vcpu_pages[cpu * PAGE_SIZE]);
	rc = (int)lowvisor_call(LOWVISOR_CALL_SHARE_VCPU_PAGE, (unsigned long)(__pa(pvp)), 0, 0);
	if (rc)
		*ret = rc;

	put_cpu();
}

int lowvisor_call_setup_stage2(lzproc_t *lzproc)
{
	int rc = lowvisor_call(LOWVISOR_CALL_SETUP_STAGE2, (unsigned long)lzproc, lzproc->hcr, 0);
	if (rc >= 0) {
		lzproc->vtcr = 64 - rc;
		printk(KERN_INFO "lightzone: PA bits of guest is %d\n", (int)VTCR_EL2_IPA(lzproc->vtcr));
		rc = 0;
	}
	return rc;
}

int lowvisor_call_share_all_vcpu_pages(void)
{
	int ret = 0;

	if (!all_per_vcpu_pages) {
		all_per_vcpu_pages = (char *)alloc_pages_exact(num_possible_cpus() * PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
		if (!all_per_vcpu_pages)
			ret = -ENOMEM;
	}

	if (!ret)
		on_each_cpu(smp_share_vcpu_page, &ret, 1);

	if (ret)
		printk(KERN_ERR "lightzone: Per-VCPU paravirt page register failed\n");
	else {
		printk(KERN_INFO "lightzone: Per-VCPU paravirt page registered\n");
		vcpu_pages_registered = true;

		ret = (int)lowvisor_call(LOWVISOR_CALL_SETUP_NESTED_MMUS, 2, 0, 0);
		if (ret)
			printk(KERN_ERR "lightzone: Nested MMUs register failed\n");
		else {
			printk(KERN_INFO "lightzone: Nested MMUs registered\n");
			ret = (int)lowvisor_call(LOWVISOR_CALL_SETUP_SHARED_REGS, 64, 0, 0);
			if (ret)
				printk(KERN_ERR "lightzone: Shared pt_regs register failed\n");
			else
				printk(KERN_INFO "lightzone: Shared pt_regs registered\n");
		}
	}

	return ret;
}

static int stage1_notifier_clear_flush_young(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	unsigned long ostart = start;

	spin_lock(&lzproc->proc_lock);
	for (; start < end; start += PAGE_SIZE)
		rc |= pt_op_young(lzproc, add_hva_offset(start, lzproc), true);
	if ((lzproc->hcr & HCR_VM) && ostart < lzproc->per_gate_end && end > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	if (ostart <= lzproc->vbar && end >= lzproc->vbar) {
		printk(KERN_INFO "lightzone: Clear flush young vbar\n");
		atomic_set(&lzproc->vbar_unmapped, 1);
	}
	spin_unlock(&lzproc->proc_lock);
	if (rc)
		PV_lz_flush_tlb_by_vmid_s1(lzproc, 0);
	return rc;
}

static int stage1_notifier_clear_young(struct mmu_notifier *subscription,
				 struct mm_struct *mm, unsigned long start, unsigned long end)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	unsigned long ostart = start;

	spin_lock(&lzproc->proc_lock);
	for (; start < end; start += PAGE_SIZE)
		rc |= pt_op_young(lzproc, add_hva_offset(start, lzproc), true);
	if ((lzproc->hcr & HCR_VM) && ostart < lzproc->per_gate_end && end > lzproc->per_gate_start)
		lz_gate_tab_destroy(lzproc);
	if (ostart <= lzproc->vbar && end >= lzproc->vbar) {
		printk(KERN_INFO "lightzone: Clear young vbar\n");
		atomic_set(&lzproc->vbar_unmapped, 1);
	}
	spin_unlock(&lzproc->proc_lock);
	return rc;
}

static int stage1_notifier_test_young(struct mmu_notifier *subscription,
			  struct mm_struct *mm, unsigned long address)
{
	int rc = 0;
	lzproc_t *lzproc = container_of_safe(subscription, lzproc_t, mn);
	spin_lock(&lzproc->proc_lock);
	rc |= pt_op_young(lzproc, add_hva_offset(address, lzproc), false);
	spin_unlock(&lzproc->proc_lock);
	return rc;
}

static const struct mmu_notifier_ops lz_npt_mmu_notifier_ops = {
	.clear_flush_young		= stage1_notifier_clear_flush_young,
	.clear_young			= stage1_notifier_clear_young,
	.test_young				= stage1_notifier_test_young,
	.change_pte				= stage2_notifier_change_pte,
	.invalidate_range_start	= stage2_notifier_invalidate_range_start,
	.invalidate_range_end	= stage2_notifier_invalidate_range_end,
	.invalidate_range		= stage2_notifier_invalidate_range,
};

int guest_lz_register_notifier(lzproc_t *lzproc)
{
	lzproc->mn.ops = &lz_npt_mmu_notifier_ops;
	return __mmu_notifier_register(&lzproc->mn, lzproc->host_mm);
}

int lowvisor_call_npt_inv_action(lzproc_t *lzproc, lzpage_t *pvp)
{
	asm volatile (
		"mov x0, %0\n\t"
		"hvc #3"
		:: "r" ((unsigned long)lzproc) : "x0", "memory"
	);
	pvp->vma_idx = 0;
	return 0;
}

int guest_npt_inv_ipa(lzproc_t *lzproc, pgd_t *s2_pgd_base, unsigned long ipa, int lev, lzpage_t *pvp)
{
	unsigned long nr_pages;

	switch (lev) {
		case 0: ipa &= PAGE_MASK; nr_pages = 1; break;
		case 1: ipa &= PMD_MASK;  nr_pages = PTRS_PER_PTE; break;
		case 2: ipa &= PUD_MASK;  nr_pages = PTRS_PER_PTE * PTRS_PER_PTE; break;
		default: ipa &= P4D_MASK; nr_pages = PTRS_PER_PTE * PTRS_PER_PTE * PTRS_PER_PTE; break;
	}

	if (pvp->vma_idx == 0 || pvp->unmap_areas[pvp->vma_idx - 1].discont_end != ipa) {
		pvp->vma_idx++;
		pvp->unmap_areas[pvp->vma_idx - 1].discont_begin = ipa;
	}
	while ((lev--) > 0)
		nr_pages *= PTRS_PER_PTE;
	pvp->unmap_areas[pvp->vma_idx - 1].discont_end = ipa + nr_pages * PAGE_SIZE;

	if (unlikely(pvp->vma_idx == NR_LOWVISOR_CALL_DISCONT_VMA))
		lowvisor_call_npt_inv_action(lzproc, pvp);

	return 0;
}

int lowvisor_call_handle_nested_page_fault(lzproc_t *lzproc, unsigned long ipa,
			unsigned long hpa, unsigned long flags)
{
	unsigned long rc = 0;

	if (lzproc->hcr & HCR_VM) {
		asm volatile (
			"mov x0, %1\n\t"
			"mov x1, %2\n\t"
			"mov x2, %3\n\t"
			"mov x3, %4\n\t"
			"hvc #4\n\t"
			"mov %0, x0"
			: "=r" (rc) : "r" ((unsigned long)lzproc), "r"(ipa), "r"(hpa), "r"(flags) :
				"x0", "x1", "x2", "x3", "memory"
		);
	}

	return (int)rc;
}

int lowvisor_call_destroy_nested_pgtable(lzproc_t *lzproc)
{
	return (int)lowvisor_call(LOWVISOR_CALL_ZAP_STAGE2, (unsigned long)lzproc, 0, 0);
}

int lowvisor_call_setup_pt_regs(struct pt_regs *regs, lzcpu_t *lzcpu)
{
	unsigned long flags, par;

	local_irq_save(flags);
	asm volatile("at s1e1r, %0" :: "r" (regs));
	isb();
	par = (read_sysreg_par() & GENMASK(43, 12)) + ((unsigned long)regs & ~PAGE_MASK);
	local_irq_restore(flags);

	lzcpu->pt_regs_pa = par;

	return (int)lowvisor_call(LOWVISOR_CALL_SETUP_PT_REGS, par, 0, 0);
}

int lowvisor_call_zap_pt_regs(unsigned long regs_pa)
{
	return (int)lowvisor_call(LOWVISOR_CALL_ZAP_PT_REGS, regs_pa, 0, 0);
}

int lowvisor_call_eager_fault_stage2(unsigned long hva, unsigned long hpfar, unsigned long esr)
{
	return (int)lowvisor_call(LOWVISOR_CALL_KVM_GUEST_ABORT, hva, hpfar, esr);
}

unsigned long guest_convert_seqpa(unsigned long aligned_seqpa, unsigned long hva, int lev)
{
	unsigned long offset;

	switch (lev) {
		case 0: offset = hva & (~PAGE_MASK); break;
		case 1: offset = hva & (~PMD_MASK); break;
		case 2: offset = hva & (~PUD_MASK); break;
		default: offset = hva & (~P4D_MASK);
	}
	return aligned_seqpa + offset;
}

#endif