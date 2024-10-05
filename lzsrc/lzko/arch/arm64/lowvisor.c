#include <asm/syscall.h>
#include <asm/tlbflush.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_mmu.h>
#include <linux/smp.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <linux/irqchip/arm-gic-v3.h>

#include "lightzone.h"
#include "npt.h"
#include "pt.h"
#include "nohammer.h"
#include "lzarm.h"
#include "lzcpu.h"
#include "lzsym.h"
#include "hwdefs.h"
#include "lowvisor.h"

#ifdef RUN_ON_VHE_HOST

/* 
 * The relationship between GPA, SEQPA, HVA, HPA
 * 
 * From the view of host/guest Linux kernel,
 * 		LIGHTZONE PAGE FAULT
 * 			1. Given HVA, find PA and SEQPA. HVA->PA; HVA<->SEQPA[3] (can be reversed).
 * 			2. Stage1 is HVA->SEQPA, stage2 is SEQPA->PA.
 * 		MMU NOTIFIER
 * 			1. Given HVA, find all SEQPA->PA mappings that are caused by the HVA. Since HVA can only be
 * 			   in one state in (4K, 2M, 1G) at the same time, we can simply walk the stage1 and stage2
 * 			   page tables.
 * 
 * From the view of the hypervisor,
 * 		LIGHTZONE STAGE2 PAGE FAULT
 * 			1. Given GPA and SEQPA, if the guest kernel is wrong, GPA->SEQPA[3]; otherwise GPA->SEQPA.
 * 			   At most 3 fixed SEQPAs (4K, 2M, 1G) are in the stage 2 page table.
 * 			2. Given GPA, the HVA is fixed, and given HVA, HPA is fixed. GPA->HVA->HPA.
 * 			3. Therefore, it might be SEQPA[0,1,2,3]->HPA, which is fixed given a GPA.
 * 		HOST MMU NOTIFIER
 * 			1. Given HVA, HVA->GPA[n], which is tracked by the hypervisor.
 * 			2. Since GPA[n] are fixed, GPA[n]->SEQPA[3*n].
 * 			3. We should guarantee that all potential mappings in the stage2 pgtable established by 
 * 			   the given HVA should be destroyed.
 * 			4. Even though a wrong kernel leads to a sequential number is mapped by several GPAs, it is
 * 			   correct because it only causes excessive page faults. Like, if [SEQ33] can be established
 * 			   by several HVAs, then no matter which HVA finally influences the PTE of stage2 page table,
 * 			   the PTE will be destroyed.
 * 			                  / [SEQ11]
 * 			         / [GPA1] ...
 *			   [HVA] - [GPA2] ...
 * 			         \ [GPA3] ...
 * 			                  \
 * 			           [GPAx] - [SEQ33]
 * 		KVM MEMSLOT CHANGE
 * 			The same as above.
 */

#define lowvisor_traverse_inv_action()			do {\
			for (; gpa_start < gpa_end; gpa_start += PAGE_SIZE) {\
				if (host_proc->counters.seqtable_base) {\
					phys_addr_t seq = pa_to_seq(gpa_start, host_proc, NULL, 0);\
					int ia_bits = VTCR_EL2_IPA(host_proc->vtcr);\
					if (seq) {\
						if (invalidate)\
							rc |= npt_inv_ipa(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)), seq);\
						else\
							rc |= npt_op_young_ipa(host_proc, seq, clear);\
					}\
					if (gpa_start & ~PMD_MASK)\
						seq = pa_to_seq(gpa_start & PMD_MASK, host_proc, NULL, 0) + (gpa_start & ~PMD_MASK);\
					if (seq & PMD_MASK) {\
						if (invalidate)\
							rc |= npt_inv_ipa(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)),\
									seq + (SEQ_PMD_BASE << (ia_bits - 4)));\
						else\
							rc |= npt_op_young_ipa(host_proc, seq + (SEQ_PMD_BASE << (ia_bits - 4)), clear);\
					}\
					if (gpa_start & ~PUD_MASK)\
						seq = pa_to_seq(gpa_start & PUD_MASK, host_proc, NULL, 0) + (gpa_start & ~PUD_MASK);\
					if (seq & PUD_MASK) {\
						if (invalidate)\
							rc |= npt_inv_ipa(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)),\
									seq + (SEQ_PUD_BASE << (ia_bits - 4)));\
						else\
							rc |= npt_op_young_ipa(host_proc, seq + (SEQ_PUD_BASE << (ia_bits - 4)), clear);\
					}\
				} else {\
					if (invalidate)\
						rc |= npt_inv_ipa(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)), gpa_start);\
					else\
						rc |= npt_op_young_ipa(host_proc, gpa_start, clear);\
				}\
			}\
		} while(0)

extern u64 host_init_cnthctl_el2;

#define LOWVISOR_DETECT_GICV_REG	(1 << 0)
#define LOWVISOR_DETECT_FEAT_TRF	(1 << 1)

static u64 lowvisor_detect_feat = 0;
static LIST_HEAD(glzgprocs);
static LIST_HEAD(glzsregs);
static LIST_HEAD(gptrlzpages);
static spinlock_t big_lowvisor_lock;

static DEFINE_PER_CPU(lzproc_t *, last_guest_proc) = NULL;
static DEFINE_PER_CPU(lzsregs_t *, last_sregs) = NULL;
static DEFINE_PER_CPU(ptr_lzpage_t *, last_pv_page) = NULL;

static int (*original_handle_hvc)(struct kvm_vcpu *);
static int (*original_kvm_vcpu_release)(struct inode *inode, struct file *filp);
static int (*original_kvm_vm_release)(struct inode *inode, struct file *filp);
static bool (*original_sysreg_fault)(struct kvm_vcpu *, u64 *);

// TODO: should we inc earlier in the finding proc function???
#define lowvisor_ret_if_busy(proc, rc)	{atomic64_inc(&proc->nr_users);\
										if (spin_is_locked(&proc->lowvisor_lock)) {\
											atomic64_dec(&proc->nr_users);\
											return rc;\
										}}

static lzproc_t *find_kvm_proc(struct kvm *kvm)
{
	struct list_head *pos;
	lzproc_t *tmp;
	lzproc_t *ret = NULL;

	spin_lock(&big_lowvisor_lock);
	list_for_each(pos, &glzgprocs) {
		tmp = list_entry(pos, lzproc_t, list_proc);
		if (tmp->kvm == kvm) {
			ret = tmp;
			break;
		}
	}
	spin_unlock(&big_lowvisor_lock);
	return ret;
}

static lzsregs_t *find_kvm_sregs(struct kvm *kvm)
{
	struct list_head *pos;
	lzsregs_t *tmp;
	lzsregs_t *ret = NULL;

	spin_lock(&big_lowvisor_lock);
	list_for_each(pos, &glzsregs) {
		tmp = list_entry(pos, lzsregs_t, list_sregs);
		if (tmp->kvm == kvm) {
			ret = tmp;
			break;
		}
	}
	spin_unlock(&big_lowvisor_lock);
	return ret;
}

static lzproc_t *find_host_proc(struct kvm *kvm, unsigned long guest_proc, bool may_create)
{
	struct list_head *pos;
	lzproc_t *tmp;
	lzproc_t *proc = NULL, *free_kvm_proc = NULL;

	lzproc_t *last_proc = this_cpu_read(last_guest_proc);
	
	if (last_proc && last_proc->guest_proc == guest_proc && last_proc->kvm == kvm)
		return last_proc;	/* fast path */
	
	spin_lock(&big_lowvisor_lock);

	list_for_each(pos, &glzgprocs) {
		tmp = list_entry(pos, lzproc_t, list_proc);
		if (tmp->kvm == kvm) {
			if (tmp->guest_proc == guest_proc) {
				proc = tmp;
				break;
			}
			if (!tmp->guest_proc)
				free_kvm_proc = tmp;
		}
	}

	if (!proc && may_create && free_kvm_proc) {
		proc = free_kvm_proc;
		proc->guest_proc = guest_proc;
	}

	spin_unlock(&big_lowvisor_lock);

	this_cpu_write(last_guest_proc, proc);

	return proc;
}

static lzpage_t *find_pv_page(struct kvm_vcpu *vcpu, unsigned long gpa, bool may_create)
{
	struct list_head *pos;
	ptr_lzpage_t *tmp, *last_page;
	unsigned long hva;
	struct page *page;
	int rc;
	bool should_map_pv_page = false;

	if (may_create)
		preempt_disable();

	last_page = this_cpu_read(last_pv_page);
	if (last_page && last_page->vcpu == vcpu) {
		if (may_create)
			preempt_enable();
		return last_page->pvp;
	}

	last_page = NULL;

	spin_lock(&big_lowvisor_lock);

	list_for_each(pos, &gptrlzpages) {
		tmp = list_entry(pos, ptr_lzpage_t, list_ptr_lzpage);
		if (tmp->vcpu == vcpu) {
			last_page = tmp;
			break;
		}
	}

	if (!last_page && may_create && !kvm_is_error_hva(hva = gfn_to_hva(vcpu->kvm, gpa_to_gfn(gpa)))) {
		last_page = kzalloc(sizeof(ptr_lzpage_t), __GFP_HIGH | __GFP_ATOMIC);
		if (last_page) {
			last_page->host_mm	= current->mm;
			last_page->vcpu		= vcpu;
			last_page->kvm		= vcpu->kvm;
			INIT_LIST_HEAD(&last_page->list_ptr_lzpage);
			list_add(&last_page->list_ptr_lzpage, &gptrlzpages);
			should_map_pv_page = true;
		}
	}

	spin_unlock(&big_lowvisor_lock);

	this_cpu_write(last_pv_page, last_page);

	if (may_create)
		preempt_enable();

	/*
	 * Before the page is mapped, this VCPU never returns to GUEST.
	 * Hence, we do not worry about the later atomic context will
	 * trigger a page fault that might cause the current context
	 * to sleep.
	 */
	if (should_map_pv_page) {

		might_fault();

		mmap_read_lock(current->mm);
		rc = get_user_pages(hva, 1, FOLL_FORCE | FOLL_WRITE, &page, NULL);
		mmap_read_unlock(current->mm);
		if (rc != 1)
			goto fail_gup;

		last_page->pvp = (lzpage_t *)page_to_virt(page);
	}

	if (last_page)
		return last_page->pvp;
	return NULL;

fail_gup:
	spin_lock(&big_lowvisor_lock);
	list_del(&last_page->list_ptr_lzpage);
	spin_unlock(&big_lowvisor_lock);
	this_cpu_write(last_pv_page, NULL);
	kfree(last_page);
	return NULL;
}

static lzsregs_t *find_sregs(struct kvm *kvm, unsigned long regs, bool may_create)
{
	struct list_head *pos;
	lzsregs_t *tmp;
	int idx, rc;
	unsigned long user_hva;
	lzsregs_t *sregs, *free_kvm_sregs, *last;
	struct page *page = NULL;

retry:
	sregs = free_kvm_sregs = NULL;
	last = this_cpu_read(last_sregs);
	
	if (last && last->kvm == kvm) {
		if (last->gpa == regs)
			return last;	/* fast path */
	}
	
	spin_lock(&big_lowvisor_lock);

	list_for_each(pos, &glzsregs) {
		tmp = list_entry(pos, lzsregs_t, list_sregs);
		if (tmp->kvm == kvm) {

			if (tmp->gpa == regs) {
				sregs = tmp;
				break;
			}

			if (!free_kvm_sregs && !tmp->gpa)
				free_kvm_sregs = tmp;
		}
	}

	if (!sregs && may_create && free_kvm_sregs) {
		if (page) {	// FIXME: add nr_users for guarding, no UAF for the page
			sregs = free_kvm_sregs;
			sregs->gpa = regs;
			if (sregs->hva)
				put_page(virt_to_page(sregs->hva));
			sregs->hva = (unsigned long)page_to_virt(page) + (regs & ~PAGE_MASK);
		} else if ((regs & PAGE_MASK) == ((unsigned long)(&(((struct pt_regs *)regs)->pstate)) & PAGE_MASK)) {
			spin_unlock(&big_lowvisor_lock);
			preempt_enable();
			goto pt_regs_gup;
		} else
			printk(KERN_INFO "lightzone: Lowvisor find pt_regs cross a page\n");
	}

	spin_unlock(&big_lowvisor_lock);
	this_cpu_write(last_sregs, sregs);

	if (!sregs && page)
		put_page(page);

	return sregs;

pt_regs_gup:
	idx = srcu_read_lock(&kvm->srcu);

	mmap_read_lock(current->mm);
	if (!kvm_is_error_hva(user_hva = gfn_to_hva(kvm, gpa_to_gfn(regs))))
		rc = get_user_pages(user_hva, 1, FOLL_FORCE | FOLL_WRITE, &page, NULL);
	else
		rc = 0;
	mmap_read_unlock(current->mm);

	srcu_read_unlock(&kvm->srcu, idx);

	preempt_disable();
	if (rc != 1)
		return NULL;
	goto retry;
}

noinline static void lowvisor_flush_tlb(struct kvm_vcpu *vcpu)
{
	lzproc_t *host_proc;
	u64 val, vtcr, vttbr, tcr_el1, sctlr_el1;

	host_proc = find_host_proc(vcpu->kvm, vcpu_get_reg(vcpu, 0), false);
	if (!host_proc)
		return;

	lowvisor_ret_if_busy(host_proc,);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		val = tcr_el1 = read_sysreg_el1(SYS_TCR);
		val |= TCR_EPD1_MASK | TCR_EPD0_MASK;
		write_sysreg_el1(val, SYS_TCR);
		val = sctlr_el1 = read_sysreg_el1(SYS_SCTLR);
		val |= SCTLR_ELx_M;
		write_sysreg_el1(val, SYS_SCTLR);
	}

	dsb(ishst);

	vtcr = read_sysreg(vtcr_el2);
	vttbr = read_sysreg(vttbr_el2);
	write_sysreg(host_proc->vtcr, vtcr_el2);
	write_sysreg(host_proc->vttbr, vttbr_el2);

	isb();
	
	__tlbi(vmalls12e1is);

	dsb(ish);
	isb();

	write_sysreg(vttbr, vttbr_el2);
	write_sysreg(vtcr, vtcr_el2);
	isb();

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/* Restore the registers to what they were */
		write_sysreg_el1(tcr_el1, SYS_TCR);
		write_sysreg_el1(sctlr_el1, SYS_SCTLR);
	}

	atomic64_dec(&host_proc->nr_users);
}

static inline unsigned long process_enter_exit(lzproc_t *proc, lzpage_t *pvp, struct pt_regs *regs, struct kvm_vcpu *vcpu)
{
#if defined(CONFIG_ARM64_MTE) || defined(CONFIG_ARM64_PTR_AUTH) || defined(CONFIG_ARM64_RAS_EXTN)
#warning "Please switch context for MTE, RAS and PA in LightZone switch!"
#endif
	unsigned long exit_code;
	extern char lz_hyp_vector[];
	extern unsigned long lz_vm_entry(struct pt_regs *regs);
	u64 vttbr, hcr, vbar_hyp, spsr, elr, ich_hcr, mdcr, cptr;
	u64 sp_guest, ttbr0_guest,  ttbr1_guest, vbar_guest, tcr_guest;
	u64 sctlr_guest, mair_guest, contextidr_guest, amair_guest,
		tpidr_guest, csselr_guest, cntkctl_guest,
		cntvctl_guest, cntvcval_guest, cntvtval_guest;	/* Virtual timer register need FEAT_ECV */
	/*
	 * Refer to KVM, and absent register (e.g. ZCR_EL1) and trivial ones (e.g. PAR_EL1) are ignored,
	 * Some registers, such as PA MTE MDCCINT, are monitored by CNTHCTL, MDCR, CPTR and HCR
	 * 
	 * CPTR_EL2: the guest OS switches FPU, SVE, SME, state for processes, so it is the guest kernel's
	 * job (and the kernel module for control register such as ZCR_EL1) rather than the Lowvisor's to
	 * switch these registers for efficiency.
	 * 
	 * ICH_HCR_EL2: When the active GIC version >= 3, we use this register to prevent the LightZone
	 * process from accessing the GICV interface, though it can be interrupted by the interrupt signal.
	 */
	char *host_vectors;

	/* Save guest OS registers that should never be changed, but not trapped by HCR_EL2 */
	if (proc->hcr & HCR_VM) {
		sctlr_guest =		read_sysreg_el1(SYS_SCTLR);
		mair_guest =		read_sysreg_el1(SYS_MAIR);
		contextidr_guest =	read_sysreg_el1(SYS_CONTEXTIDR);
		amair_guest =		read_sysreg_el1(SYS_AMAIR);
	}
	tpidr_guest =		read_sysreg_s(SYS_TPIDR_EL1);
	csselr_guest =		read_sysreg_s(SYS_CSSELR_EL1);
	cntkctl_guest = 	read_sysreg_el1(SYS_CNTKCTL);
	cntvctl_guest =		read_sysreg(cntv_ctl_el0);
	cntvcval_guest =	read_sysreg(cntv_cval_el0);
	cntvtval_guest =	read_sysreg(cntv_tval_el0);

	/* Save guest OS system registers different from LightZone. */
	sp_guest =			read_sysreg(sp_el1);
	ttbr0_guest =		read_sysreg_el1(SYS_TTBR0);
	ttbr1_guest =		read_sysreg_el1(SYS_TTBR1);
	vbar_guest = 		read_sysreg_el1(SYS_VBAR);
	tcr_guest =			read_sysreg_el1(SYS_TCR);

	/* Restore LightZone process system registers. */
	write_sysreg(pvp->sp_el1,		sp_el1);
	write_sysreg_el1(0,				SYS_ELR);
	write_sysreg_el1(pvp->spsr_el1,	SYS_SPSR);
	write_sysreg_el1(pvp->ttbr0_el1,SYS_TTBR0);
	write_sysreg_el1(pvp->ttbr1_el1,SYS_TTBR1);
	write_sysreg_el1(pvp->vbar_el1,	SYS_VBAR);
	write_sysreg_el1(pvp->tcr_el1,	SYS_TCR);

	/* Save KVM EL2 registers. */
	vbar_hyp =			read_sysreg(vbar_el1);
	spsr = 				read_sysreg_el2(SYS_SPSR);
	elr =				read_sysreg_el2(SYS_ELR);
	mdcr =				read_sysreg(mdcr_el2);
	cptr =				read_sysreg(cpacr_el1);
	if ((lowvisor_detect_feat & LOWVISOR_DETECT_GICV_REG) &&
			(read_gicreg(ICC_SRE_EL2) & ICC_SRE_EL2_ENABLE)) {
		ich_hcr = read_gicreg(ICH_HCR_EL2);
		write_gicreg(ich_hcr | LZ_ICH_HCR_SET_VAL, ICH_HCR_EL2);
	}
	if (unlikely((mdcr & LZ_MDCR_SET_VAL) != (LZ_MDCR_SET_VAL & ~(
		(lowvisor_detect_feat & LOWVISOR_DETECT_FEAT_TRF) ? 0 : MDCR_EL2_TTRF
	))))
		write_sysreg(mdcr | LZ_MDCR_SET_VAL, mdcr_el2);
	/* For NVHE, the physical access is disabled by the HYPERVISOR */
	write_sysreg(host_init_cnthctl_el2 & ~LZ_CNTHCTL_UNSET_VAL, cnthctl_el2);
	write_sysreg((cptr & (CPACR_EL1_FPEN_EL1EN
			| CPACR_EL1_FPEN_EL0EN)) | LZ_CPTR_SET_VAL, cpacr_el1);

	/*************** Activate traps. ***************/
	vttbr =	read_sysreg(vttbr_el2);
	if (proc->hcr & HCR_VM)
		write_sysreg(proc->vttbr, vttbr_el2);
	else {
		int vmid_bit = (proc->vtcr & VTCR_EL2_VS_16BIT) ? 16 : 8;
		write_sysreg((proc->vttbr & VTTBR_VMID_MASK(vmid_bit)) |
					 (vttbr & ~VTTBR_VMID_MASK(vmid_bit)), vttbr_el2);
		hcr = read_sysreg(hcr_el2);
		write_sysreg(hcr | HCR_TVM, hcr_el2);
	}
	isb();

	host_vectors = (char *)vbar_hyp;
	write_sysreg((unsigned long)lz_hyp_vector, vbar_el1);

	write_sysreg_el2(pvp->elr_el2, SYS_ELR);
	write_sysreg_el2(pvp->spsr_el2, SYS_SPSR);

	exit_code = lz_vm_entry(regs);
	this_cpu_write(lz_guest_ctxt, NULL);

	/* 
	 * Restore LightZone process in-VM context.
	 */
	pvp->esr_el2 = read_sysreg_el2(SYS_ESR);
	pvp->elr_el2 = read_sysreg_el2(SYS_ELR);
	if (ESR_ELx_EC(pvp->esr_el2) == ESR_ELx_EC_IABT_LOW ||
			ESR_ELx_EC(pvp->esr_el2) == ESR_ELx_EC_DABT_LOW) {
		pvp->far_el2 = read_sysreg_el2(SYS_FAR);
		if (!(pvp->esr_el2 & ESR_ELx_S1PTW) &&
			(cpus_have_final_cap(ARM64_WORKAROUND_834220) ||
			(pvp->esr_el2 & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
			if (!__kvm_at("s1e1r", pvp->far_el2))
				pvp->hpfar_el2 = PAR_TO_HPFAR(read_sysreg_par());
			else
				exit_code = ARM_EXCEPTION_IL;
		} else
			pvp->hpfar_el2 = read_sysreg(hpfar_el2);
	} else if (ESR_ELx_EC(pvp->esr_el2) == ESR_ELx_EC_HVC64) {
		pvp->far_el1 = read_sysreg_el1(SYS_FAR);
		pvp->esr_el1 = read_sysreg_el1(SYS_ESR);
	}
	pvp->elr_el1 = read_sysreg_el1(SYS_ELR);
	pvp->spsr_el1 = read_sysreg_el1(SYS_SPSR);
	pvp->sp_el1 = read_sysreg(sp_el1);
	pvp->ttbr0_el1 = read_sysreg_el1(SYS_TTBR0);
	pvp->spsr_el2 = read_sysreg_el2(SYS_SPSR);

	/* Check guest OS registers that should never be changed, but not trapped by HCR_EL2 */
	if (proc->hcr & HCR_VM) {
		write_sysreg_el1(sctlr_guest,		SYS_SCTLR);
		write_sysreg_el1(mair_guest,		SYS_MAIR);
		write_sysreg_el1(contextidr_guest,	SYS_CONTEXTIDR);
		write_sysreg_el1(amair_guest,		SYS_AMAIR);
	}
	write_sysreg_s(tpidr_guest,			SYS_TPIDR_EL1);
	write_sysreg_s(csselr_guest,		SYS_CSSELR_EL1);
	write_sysreg_el1(cntkctl_guest,		SYS_CNTKCTL);
	write_sysreg(cntvctl_guest,			cntv_ctl_el0);
	write_sysreg(cntvcval_guest,		cntv_cval_el0);
	write_sysreg(cntvtval_guest,		cntv_tval_el0);
	
	/* Restore Guest OS registers. */
	write_sysreg(sp_guest,						sp_el1);
	write_sysreg_el1(ttbr0_guest,				SYS_TTBR0);
	write_sysreg_el1(ttbr1_guest,				SYS_TTBR1);
	write_sysreg_el1(vbar_guest,				SYS_VBAR);
	write_sysreg_el1(tcr_guest,					SYS_TCR);

	/* Restore KVM EL2 Registers. */
	write_sysreg(vttbr, vttbr_el2);
	if (!(proc->hcr & HCR_VM))
		write_sysreg(hcr, hcr_el2);
	isb();
	write_sysreg(host_vectors, vbar_el1);
	write_sysreg_el2(spsr, SYS_SPSR);
	write_sysreg_el2(elr, SYS_ELR);

	if ((lowvisor_detect_feat & LOWVISOR_DETECT_GICV_REG) &&
			(read_gicreg(ICC_SRE_EL2) & ICC_SRE_EL2_ENABLE))
		write_gicreg(ich_hcr, ICH_HCR_EL2);
	if (unlikely((mdcr & LZ_MDCR_SET_VAL) != (LZ_MDCR_SET_VAL & ~(
		(lowvisor_detect_feat & LOWVISOR_DETECT_FEAT_TRF) ? 0 : MDCR_EL2_TTRF
	))))
		write_sysreg(mdcr, mdcr_el2);
#ifdef LAZY_VHE_LOWVISOR_OPT
#else
	write_sysreg(host_init_cnthctl_el2 | LZ_CNTHCTL_UNSET_VAL, cnthctl_el2);
#endif
	write_sysreg(cptr, cpacr_el1);

	return exit_code;
}

static bool lowvisor_prehandle_sysreg_fault(struct kvm_vcpu *vcpu, u64 *exit_code)
{
#ifdef LAZY_VHE_LOWVISOR_OPT
	u64 iss = kvm_vcpu_get_esr(vcpu) & ESR_ELx_SYS64_ISS_SYS_MASK;

	/*
	 * ===========================================================
	 * 24	23	22	21	20	19	18	17	16	15	14	13	12	11	10
	 * RES0			Op0		Op2			Op1			CRn
	 * ===========================================================
	 * 9	8	7	6	5	4	3	2	1	0
	 * Rt					CRm				Direction
	 * ===========================================================
	 * 
	 * 3,3,{1,5},14,0
	 * SYS_CNTPCTSS_EL0 ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 5, 14, 0)
	 * CNTPCT_EL0		ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 1, 14, 0)
	 * 
	 * 3,3,x,14,2:
	 * CNTP_CTL_EL0		ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 1, 14, 2)
	 * CNTP_CVAL_EL0	ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 2, 14, 2)
	 * CNTP_TVAL_EL0	ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 0, 14, 2)
	 */
	if (iss == ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 5, 14, 0) ||
		iss == ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 1, 14, 0) ||
		iss == ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 1, 14, 2) ||
		iss == ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 2, 14, 2) ||
		iss == ESR_ELx_SYS64_ISS_SYS_VAL(3, 3, 0, 14, 2)) {
		write_sysreg(host_init_cnthctl_el2 | LZ_CNTHCTL_UNSET_VAL, cnthctl_el2);
		return true;
	}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
	return false;
#else
	return original_sysreg_fault(vcpu, exit_code);
#endif
}

noinline static unsigned long lowvisor_nested_vm_enter_exit(struct kvm_vcpu *vcpu)
{
	lzproc_t *host_proc;
	unsigned long rc;
	lzsregs_t *sregs = find_sregs(vcpu->kvm, vcpu_get_reg(vcpu, 0), false);
	lzpage_t *pvp = find_pv_page(vcpu, 0, false);

	if (!pvp || !sregs)
		return ARM_EXCEPTION_IRQ;
	host_proc = find_host_proc(vcpu->kvm, pvp->guest_proc_va, false);
	if (!host_proc)
		return ARM_EXCEPTION_IRQ;
	lowvisor_ret_if_busy(host_proc, -EINVAL);

	if (lz_assign_vmid(host_proc, true)) {
		atomic64_dec(&host_proc->nr_users);
		return ARM_EXCEPTION_NO_VMID;
	}
	lz_assign_vmid_lock(host_proc);

	rc = process_enter_exit(host_proc, pvp, (struct pt_regs *)(sregs->hva), vcpu);

	atomic64_dec(&host_proc->nr_users);

	return rc;
}

inline static bool lowvisor_validate_and_set_seqpa(unsigned long ipa, lzproc_t *host_proc,
			unsigned long seqpa, int max_lev)
{
	/* 
	 * The granualrity of GPA is not necessarily equal to that of HVA.
	 * 	[1]	When the granularity is the same, say 2MB, ipa, hostpa, and hva are always 2MB aligned.
	 * 	[2] When ipa and seqpa are 2MB, host is 4KB, use 2MB alignment in the ipa->seq table.
	 * 		In the MMU notifier, since the 4KB IPA does not have a mapping, it will search for its 2MB and 1GB
	 * 		aligned IPAs in the ipa->seqpa table.
	 * 	[3] When ipa and seqpa are 4KB, host is 2MB, in the ipa->seqpa table, the index, IPA, is 4KB aligned.
	 * 		In the later MMU notifier, since the augment is PAGE_SIZE (4KB), the stage2 mapping can be zapped.
	 */
	if (host_proc->hcr & HCR_VM)
		return check_pa_to_seq(ipa, host_proc, seqpa, max_lev);
	return false;
}

noinline static int lowvisor_handle_guest_abort(struct kvm_vcpu *vcpu, bool inner_loop)
{
	struct kvm_memory_slot *memslot;
	struct kvm *kvm;
	unsigned long hva, hpa;
	bool writable;
	gfn_t gfn;
	pte_t *hpte;
	int rc, idx, level;
	lzproc_t *host_proc;
	unsigned long fault_flags, vm_flags, mm_flags;
	struct vm_area_struct *vma;
	unsigned long flags = vcpu_get_reg(vcpu, 3);
	unsigned long ipa = vcpu_get_reg(vcpu, 2) & PAGE_MASK;
	unsigned long seqpa = vcpu_get_reg(vcpu, 1) & PAGE_MASK;
	spinlock_t *ptl = NULL;

	/* flags S2 must be set, other bits dont need sanitizing */
	if (inner_loop)
		flags |= LZ_PF_IN_GUEST;
	else
		flags &= ~LZ_PF_IN_GUEST;

	kvm = vcpu->kvm;
	if (ipa >= BIT_ULL(IMPORTED(get_kvm_ipa_limit)()))
		return -EFAULT;
	if (ipa >= BIT_ULL(kvm->arch.mmu.pgt->ia_bits))
		return -EFAULT;

	preempt_disable();
	host_proc = find_host_proc(vcpu->kvm, vcpu_get_reg(vcpu, 0), false);
	preempt_enable();
	if (!host_proc)
		return -EINVAL;
	lowvisor_ret_if_busy(host_proc, -EINVAL);

	idx = srcu_read_lock(&kvm->srcu);

	gfn = ipa >> PAGE_SHIFT;
	memslot = gfn_to_memslot(kvm, gfn);
	hva = IMPORTED(gfn_to_hva_memslot_prot)(memslot, gfn, &writable);
	if (kvm_is_error_hva(hva) || ((flags & LZ_PF_WRITE) && !writable) || ipa >= kvm_phys_size(kvm)) {
		printk(KERN_ERR "lightzone: MMIO mapped to guest's userspace is not supported currently\n");
		rc = -EINVAL;   /* Send this unmapped MMIO ret value to the guest kernel for delegation. */
		goto out_unlock;
	}

	if (inner_loop) {
		if (!mmap_read_trylock(current->mm)) {
			rc = ARM_EXCEPTION_NO_MLOCK;
			goto out_unlock;
		}
	} else
		mmap_read_lock(current->mm);

	rc = walk_pgtable(current->mm->pgd, hva, -1, NULL, &hpte, &ptl, 0);
	if (likely(rc >= 0))
		goto fastpath;
	else if (inner_loop) {
		rc = ARM_EXCEPTION_NO_MLOCK;
		goto out;
	}

retry:
	vma = find_vma(current->mm, hva);
	if (vma) {
		if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP))
			goto out;
		if (vma->vm_flags & VM_IO)
			goto out;
	} else
		goto out;

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

	if (vma && !(vma->vm_start > hva && ((!(vma->vm_flags & VM_GROWSDOWN)) ||
			IMPORTED(expand_stack)(vma, hva))) && (vma->vm_flags & vm_flags)) {
		fault_flags = handle_mm_fault(vma, hva & PAGE_MASK, mm_flags, NULL);
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
		rc = walk_pgtable(current->mm->pgd, hva, -1, NULL, &hpte, &ptl, 0);

fastpath:   /* rc >= 0, is the level; rc < 0 is fault code */
	if (rc >= 0) {
		if (((flags & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT) >= rc) {
			level = rc;
			hpa = __pte_to_phys(*hpte);
		} else {
			unsigned long less_bits_addr, more_bits_addr;
			level = (flags & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT;
			hpa = __pte_to_phys(*hpte);
			switch (rc) {
				case 1: less_bits_addr = ipa & PMD_MASK; break;
				case 2: less_bits_addr = ipa & PUD_MASK; break;
				default: less_bits_addr = ipa & P4D_MASK;
			}
			switch (level) {
				case 0: more_bits_addr = ipa & PAGE_MASK; break;
				case 1: more_bits_addr = ipa & PMD_MASK; break;
				default: more_bits_addr = ipa & PUD_MASK;
			}
			hpa += (more_bits_addr - less_bits_addr);
		}

		if (ptl) {
			pte_unmap_unlock(hpte, ptl);
			ptl = NULL;
		}

		spin_lock(&host_proc->proc_lock);
		if (lowvisor_validate_and_set_seqpa(ipa, host_proc, seqpa,
				(flags & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT) && host_proc->s2_pgd_phys)
			rc = handle_nested_page_fault(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)),
				seqpa, hpa, level, flags);
		else
			rc = -EINVAL;
		spin_unlock(&host_proc->proc_lock);
	}

out:
	mmap_read_unlock(current->mm);

out_unlock:
	srcu_read_unlock(&kvm->srcu, idx);
	atomic64_dec(&host_proc->nr_users);
	return rc;
}

noinline static int lowvisor_unmap_flush_nested_pgtable(struct kvm_vcpu *vcpu, unsigned long guest_proc)
{
	lzproc_t *host_proc;
	lzpage_t *pvp;
	unsigned long ipa;
	int i;
	volatile int min;   /* Never TOCTOU */

	preempt_disable();
	pvp = find_pv_page(vcpu, 0, false);
	if (pvp)
		host_proc = find_host_proc(vcpu->kvm, guest_proc, false);
	preempt_enable();
	if (!host_proc || !pvp)
		return -EINVAL;
	lowvisor_ret_if_busy(host_proc, -EINVAL);

	if (pvp->vma_idx > NR_LOWVISOR_CALL_DISCONT_VMA)
		min = NR_LOWVISOR_CALL_DISCONT_VMA;
	else
		min = pvp->vma_idx;

	spin_lock(&host_proc->proc_lock);
	if (host_proc->s2_pgd_phys)
		for (i = 0; i < min; i++)
			for (ipa = pvp->unmap_areas[i].discont_begin; ipa < pvp->unmap_areas[i].discont_end; ipa += PAGE_SIZE)
				npt_inv_ipa(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)), ipa);
	spin_unlock(&host_proc->proc_lock);
	lz_flush_tlb_by_vmid(host_proc, 0, 1);

	atomic64_dec(&host_proc->nr_users);
	return 0;
}

static bool fast_lowvisor_call(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	unsigned long rc;
	u64 esr_el2 = kvm_vcpu_get_esr(vcpu);

	switch (esr_el2 & ESR_ELx_ISS_MASK) {
		case LOWVISOR_CALL_VM_SWITCH_ISS:
			rc = lowvisor_nested_vm_enter_exit(vcpu);
			if (rc != ARM_EXCEPTION_NO_VMID)
				vcpu_set_reg(vcpu, 0, rc);
			return (rc != ARM_EXCEPTION_NO_VMID);
		case LOWVISOR_CALL_TLBI_ISS: lowvisor_flush_tlb(vcpu); return true;
		case LOWVISOR_CALL_UNMAP_TLBI_ISS:
			lowvisor_unmap_flush_nested_pgtable(vcpu, vcpu_get_reg(vcpu, 0));
			return true;
		case LOWVISOR_CALL_FAULT_ISS:
			rc = lowvisor_handle_guest_abort(vcpu, true);
			if (rc != ARM_EXCEPTION_NO_MLOCK) {
				vcpu_set_reg(vcpu, 0, rc);
				return true;
			}
			return false;
		default: return false;
	}
}

static bool lowvisor_prehandler(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	u64 esr_el2 = kvm_vcpu_get_esr(vcpu);

	switch (ESR_ELx_EC(esr_el2)) {
		case ESR_ELx_EC_HVC64: return fast_lowvisor_call(vcpu, exit_code);
		case ESR_ELx_EC_SYS64: return lowvisor_prehandle_sysreg_fault(vcpu, exit_code);
		default: return false;
	}
}

static int change_kernel_pgtable_perm(unsigned long addr, bool wr)
{
	pte_t *ppte;
	int level;
	extern void lzhcr_restore(void);
	unsigned long ttbr1 = read_sysreg(ttbr1_el1);

	level = walk_pgtable(__va(ttbr1 & (~TTBR_ASID_MASK) & (~TTBR_CNP_BIT)),
					addr, -1, NULL, &ppte, NULL, 0);
	if (level >= 0) {
		if (wr)
			*ppte = __pte(pte_val(*ppte) & (~PTE_RDONLY));
		else
			*ppte = __pte(pte_val(*ppte) | PTE_RDONLY);
#ifdef TGE_OPT_EL2
		lzhcr_restore();
#endif
		dsb(ishst);
		__tlbi(vmalle1is);
		dsb(ish);
		isb();
		return 0;
	}
	return -EINVAL;
}

static void smp_zap_vcpu_page(void *info)
{
	ptr_lzpage_t *ptr;
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)info;

	preempt_disable();
	ptr = this_cpu_read(last_pv_page);
	if (ptr && ptr->vcpu == vcpu)
		this_cpu_write(last_pv_page, NULL);
	preempt_enable();
}

static inline void lowvisor_vcpu_put_pv_page(struct kvm_vcpu *vcpu)
{
	struct list_head *pos, *n;
	ptr_lzpage_t *tmp;

	on_each_cpu(smp_zap_vcpu_page, vcpu, 1);
	spin_lock(&big_lowvisor_lock);
	list_for_each_safe(pos, n, &gptrlzpages) {
		tmp = list_entry(pos, ptr_lzpage_t, list_ptr_lzpage);
		if (tmp->vcpu == vcpu) {
			list_del(&tmp->list_ptr_lzpage);
			if (tmp->pvp) {
				put_page(virt_to_page((unsigned long)(tmp->pvp)));
				tmp->pvp = NULL;
			}
			kfree(tmp);
		}
	}
	spin_unlock(&big_lowvisor_lock);
}

static void smp_zap_kvm_sregs(void *info)
{
	lzsregs_t *ptr;
	lzsregs_t *sregs = (lzsregs_t *)info;

	preempt_disable();
	ptr = this_cpu_read(last_sregs);
	if (ptr == sregs)
		this_cpu_write(last_sregs, NULL);
	preempt_enable();
}

static inline int lowvisor_destroy_shared_regs(lzsregs_t *sregs)
{
	spin_lock(&big_lowvisor_lock);
	list_del(&sregs->list_sregs);
	spin_unlock(&big_lowvisor_lock);
	
	on_each_cpu(smp_zap_kvm_sregs, sregs, 1);
	kfree(sregs);

	return 0;
}

static inline void lowvisor_kvm_put_shared_regs(struct kvm *kvm)
{
	lzsregs_t *sregs;

	for (;;) {
		sregs = find_kvm_sregs(kvm);
		if (!sregs)
			return;
		lowvisor_destroy_shared_regs(sregs);
	}
}

static void smp_zap_kvm_host_proc(void *info)
{
	lzproc_t *ptr;
	lzproc_t *proc = (lzproc_t *)info;

	preempt_disable();
	ptr = this_cpu_read(last_guest_proc);
	if (ptr == proc)
		this_cpu_write(last_guest_proc, NULL);
	preempt_enable();
}

static inline int lowvisor_destroy_flush_nested_pgtable(lzproc_t *host_proc)
{
	spin_lock(&big_lowvisor_lock);
	list_del(&host_proc->list_proc);
	spin_unlock(&big_lowvisor_lock);

	/* 
	 * From here, the to-be-freed host proc will never be filled in the 
	 * per-CPU fast path struct.
	 */

	if (host_proc->host_mm)
		mmu_notifier_unregister(&host_proc->mn, host_proc->host_mm);

	if (host_proc->s2_pgd_phys) {
		destroy_nested_pgtable(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)),
				host_proc->ia_bits, host_proc->start_level, true);
		lz_flush_tlb_by_vmid(host_proc, 0, 0);
		host_proc->s2_pgd_phys = 0;
	}
	
	on_each_cpu(smp_zap_kvm_host_proc, host_proc, 1);
	kfree(host_proc);

	return 0;
}

static inline void lowvisor_kvm_put_host_proc(struct kvm *kvm)
{
	lzproc_t *host_proc;

	for (;;) {
		host_proc = find_kvm_proc(kvm);
		if (!host_proc)
			return;
		lowvisor_destroy_flush_nested_pgtable(host_proc);
	}
}

static void lz_nested_s2_clear(struct kvm *kvm)
{
	/* stage2_unmap_walker ---- unmap a range */
	struct list_head *pos;
	lzproc_t *tmp;

	spin_lock(&big_lowvisor_lock);
	list_for_each(pos, &glzgprocs) {
		tmp = list_entry(pos, lzproc_t, list_proc);
		if (tmp->kvm == kvm && tmp->s2_pgd_phys) {
			spin_lock(&tmp->proc_lock);
			destroy_nested_pgtable(tmp, (pgd_t *)(__va(tmp->s2_pgd_phys)),
				tmp->ia_bits, tmp->start_level, false);
			spin_unlock(&tmp->proc_lock);
			lz_flush_tlb_by_vmid(tmp, 0, 0);
		}
	}
	spin_unlock(&big_lowvisor_lock);
}

static void lz_nested_s2_wp(struct kvm *kvm)
{
	/* kvm_pgtable_stage2_wrprotect ---- add S2AP_W write protect */
	/* We just clear the page table for simplicity. */
	return lz_nested_s2_clear(kvm);
}

static void lz_nested_s2_flush(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
	/* stage2_flush_walker ---- flush dcache */
	struct list_head *pos;
	lzproc_t *tmp;
	pte_t *pnpte = NULL;
	phys_addr_t addr = memslot->base_gfn << PAGE_SHIFT;
	phys_addr_t end = addr + PAGE_SIZE * memslot->npages;

	spin_lock(&big_lowvisor_lock);
	list_for_each(pos, &glzgprocs) {
		tmp = list_entry(pos, lzproc_t, list_proc);
		if (tmp->kvm == kvm && tmp->s2_pgd_phys) {
			spin_lock(&tmp->proc_lock);
			for (; addr < end; addr += PAGE_SIZE) {
				if (tmp->counters.seqtable_base) {
					phys_addr_t seq = pa_to_seq(addr, tmp, NULL, 0);
					int ia_bits = VTCR_EL2_IPA(tmp->vtcr);
					
					if (seq)
						walk_nested_pgtable((pgd_t *)(__va(tmp->s2_pgd_phys)), seq,
									tmp->start_level, -1, NULL, &pnpte);

					if (addr & ~PMD_MASK)
						seq = pa_to_seq(addr & PMD_MASK, tmp, NULL, 0) + (addr & ~PMD_MASK);
					if (seq & PMD_MASK)
						walk_nested_pgtable((pgd_t *)(__va(tmp->s2_pgd_phys)),
								seq + (SEQ_PMD_BASE << (ia_bits - 4)),
								tmp->start_level, -1, NULL, &pnpte);

					if (addr & ~PUD_MASK)
						seq = pa_to_seq(addr & PUD_MASK, tmp, NULL, 0) + (addr & ~PUD_MASK);
					if (seq & PUD_MASK)
						walk_nested_pgtable((pgd_t *)(__va(tmp->s2_pgd_phys)),
								seq + (SEQ_PUD_BASE << (ia_bits - 4)),
								tmp->start_level, -1, NULL, &pnpte);
				} else
					walk_nested_pgtable((pgd_t *)(__va(tmp->s2_pgd_phys)), addr,
							tmp->start_level, -1, NULL, &pnpte);
			}
			spin_unlock(&tmp->proc_lock);
		}
	}
	spin_unlock(&big_lowvisor_lock);
}

static void smp_zap_kvm_page(void *info)
{
	ptr_lzpage_t *ptr;
	struct kvm *kvm = (struct kvm *)info;

	preempt_disable();
	ptr = this_cpu_read(last_pv_page);
	if (ptr && ptr->kvm == kvm)
		this_cpu_write(last_pv_page, NULL);
	preempt_enable();
}

static inline void lowvisor_kvm_put_pv_page(struct kvm *kvm)
{
	struct list_head *pos, *n;
	ptr_lzpage_t *tmp;
	
	on_each_cpu(smp_zap_kvm_page, kvm, 1);
	spin_lock(&big_lowvisor_lock);
	list_for_each_safe(pos, n, &gptrlzpages) {
		tmp = list_entry(pos, ptr_lzpage_t, list_ptr_lzpage);
		if (tmp->kvm == kvm) {
			list_del(&tmp->list_ptr_lzpage);
			kfree(tmp);
		}
	}
	spin_unlock(&big_lowvisor_lock);
}

static int lz_kvm_vm_release(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = filp->private_data;

	/* Release all related host_proc first. */
	lowvisor_kvm_put_host_proc(kvm);

	/* Release all related shared regs. */
	lowvisor_kvm_put_shared_regs(kvm);

	/* Release all pv_pages related to the kvm. */
	lowvisor_kvm_put_pv_page(kvm);

	return original_kvm_vm_release(inode, filp);
}

static int lz_kvm_vcpu_release(struct inode *inode, struct file *filp)
{
	struct kvm_vcpu *vcpu = filp->private_data;

	/* Release all pv_pages related to the vcpu. */
	lowvisor_vcpu_put_pv_page(vcpu);

	return original_kvm_vcpu_release(inode, filp);
}

static __always_inline int npt_op_young_ipa(lzproc_t *lzproc, unsigned long ipa, bool clear)
{
	int inv, af;
	pte_t *pnpte;
	
	af = 0;
	inv = walk_nested_pgtable((pgd_t *)(__va(lzproc->s2_pgd_phys)), ipa,
				lzproc->start_level, -1, NULL, &pnpte);
	if (inv >= 0) {
		af = (pte_val(*pnpte) & LZ_PTE_LEAF_ATTR_LO_S2_AF);
		if (clear)
			*pnpte = __pte(pte_val(*pnpte) & (~LZ_PTE_LEAF_ATTR_LO_S2_AF));
	}

	return af;
}

static int lowvisor_notifier_op_npt(struct mmu_notifier *mn,
						unsigned long start, unsigned long end,
						bool invalidate, bool clear, bool flush)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	int i;
#endif
	unsigned long gpa_start, gpa_end;
	int rc;
	struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	int idx;
	lzproc_t *host_proc = container_of_safe(mn, lzproc_t, mn);
	struct kvm *kvm = host_proc->kvm;

	rc = 0;
	lowvisor_ret_if_busy(host_proc, -EINVAL);

	spin_lock(&host_proc->proc_lock);
	if (!host_proc->s2_pgd_phys)
		goto out;
#ifdef LAZY_VHE_LOWVISOR_OPT
	if (!invalidate)
		goto out;
#endif

	idx = srcu_read_lock(&kvm->srcu);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, slots) {
		unsigned long hva_start, hva_end;
		hva_start = max(start, memslot->userspace_addr);
		hva_end = min(end, memslot->userspace_addr +
					(memslot->npages << PAGE_SHIFT));
		if (hva_start >= hva_end)
			continue;
		gpa_start = hva_to_gfn_memslot(hva_start, memslot) << PAGE_SHIFT;
		gpa_end = gpa_start + (hva_end - hva_start);
		
		lowvisor_traverse_inv_action();
	}
#else
#define kvm_for_each_memslot_in_hva_range(node, slots, start, last)	     \
	for (node = interval_tree_iter_first(&slots->hva_tree, start, last); \
	     node;							     \
	     node = interval_tree_iter_next(node, start, last))	     \

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		struct interval_tree_node *node;

		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot_in_hva_range(node, slots,
						  start, end - 1) {
			unsigned long hva_start, hva_end;

			memslot = container_of(node, struct kvm_memory_slot, hva_node[slots->node_idx]);
			hva_start = max(start, memslot->userspace_addr);
			hva_end = min(end, memslot->userspace_addr +
						  (memslot->npages << PAGE_SHIFT));

			gpa_start = hva_to_gfn_memslot(hva_start, memslot) << PAGE_SHIFT;
			gpa_end = hva_to_gfn_memslot(hva_end + PAGE_SIZE - 1, memslot) << PAGE_SHIFT;

			lowvisor_traverse_inv_action();
		}
	}
#endif

	srcu_read_unlock(&kvm->srcu, idx);

out:
	spin_unlock(&host_proc->proc_lock);
	if ((invalidate || flush) && rc)
		lz_flush_tlb_by_vmid(host_proc, 0, 0);

	atomic64_dec(&host_proc->nr_users);

	return invalidate ? 0 : rc;
}

static int lowvisor_notifier_invalidate_range_start(struct mmu_notifier *mn,
					const struct mmu_notifier_range *range)
{
	return lowvisor_notifier_op_npt(mn, range->start, range->end, true, false, false);
}

static void lowvisor_notifier_invalidate_range(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start, unsigned long end)
{
	lowvisor_notifier_op_npt(mn, start, end, true, false, false);
}

static void lowvisor_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm, unsigned long address, pte_t pte)
{
	lowvisor_notifier_invalidate_range(mn, mm, address, address + PAGE_SIZE);
}

static void lowvisor_notifier_invalidate_range_end(struct mmu_notifier *mn,
					const struct mmu_notifier_range *range) {}

static int lowvisor_notifier_clear_flush_young(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	return lowvisor_notifier_op_npt(mn, start, end, false, true, true);
}

static int lowvisor_notifier_clear_young(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long start,
					unsigned long end)
{
	return lowvisor_notifier_op_npt(mn, start, end, false, true, false);
}

static int lowvisor_notifier_test_young(struct mmu_notifier *mn,
					   struct mm_struct *mm,
					   unsigned long address)
{
	return lowvisor_notifier_op_npt(mn, address, address + PAGE_SIZE, false, false, false);
}

// FIXME: concurrency of KVM unmap and Lightzone S2 fault
// FIXME: concurrency of qemu process unmap and Lightzone S2 fault
static const struct mmu_notifier_ops lowvisor_mmu_notifier_ops = {
	.invalidate_range		= lowvisor_notifier_invalidate_range,
	.invalidate_range_start	= lowvisor_notifier_invalidate_range_start,
	.invalidate_range_end	= lowvisor_notifier_invalidate_range_end,
	.clear_flush_young		= lowvisor_notifier_clear_flush_young,
	.clear_young			= lowvisor_notifier_clear_young,
	.test_young				= lowvisor_notifier_test_young,
	.change_pte				= lowvisor_notifier_change_pte,
};

static int lowvisor_register_notifier(lzproc_t *host_proc)
{
	host_proc->mn.ops = &lowvisor_mmu_notifier_ops;
	return __mmu_notifier_register(&host_proc->mn, host_proc->host_mm);
}

noinline static int lowvisor_setup_stage2(struct kvm_vcpu *vcpu, unsigned long proc, u64 hcr)
{
	lzproc_t *host_proc;
	int rc = -EINVAL;

	preempt_disable();
	host_proc = find_host_proc(vcpu->kvm, proc, true);
	preempt_enable();

	if (!host_proc)
		return -EINVAL;
	lowvisor_ret_if_busy(host_proc, -EINVAL);

	spin_lock(&host_proc->proc_lock);
	if (host_proc->s2_pgd_phys)
		goto fail_repeat_config;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
	host_proc->vtcr = vcpu->arch.hw_mmu->kvm->arch.vtcr;
#else
	host_proc->vtcr = vcpu->arch.hw_mmu->arch->vtcr;
#endif
	if (hcr & HCR_VM)
		host_proc->hcr = (host_proc->hcr & (~HCR_TVM)) | HCR_VM;
	else
		host_proc->hcr = (host_proc->hcr & (~HCR_VM)) | HCR_TVM;

	rc = lz_init_stage2_mmu_locked(host_proc);
	if (!rc && (hcr & HCR_VM))
		rc = lz_init_seqtable_locked(host_proc);
	if (rc >= 0)
		rc = VTCR_EL2_IPA(host_proc->vtcr);

fail_repeat_config:
	spin_unlock(&host_proc->proc_lock);
	atomic64_dec(&host_proc->nr_users);
	return rc;
}

noinline static int lowvisor_clear_flush_nested_pgtable(struct kvm_vcpu *vcpu, unsigned long guest_proc)
{
	lzproc_t *host_proc;
	
	preempt_disable();
	host_proc = find_host_proc(vcpu->kvm, guest_proc, false);
	preempt_enable();
	
	if (!host_proc)
		return -EINVAL;

	if (!spin_trylock(&host_proc->lowvisor_lock))
		return 0;

	if (atomic64_read(&host_proc->nr_users)) {
		spin_unlock(&host_proc->lowvisor_lock);
		printk(KERN_ERR "lightzone: Lowvisor finds there are still users of nested mmu to be freed\n");
		return -EINVAL;
	}

	spin_lock(&host_proc->proc_lock);
	if (host_proc->s2_pgd_phys) {
		destroy_nested_pgtable(host_proc, (pgd_t *)(__va(host_proc->s2_pgd_phys)),
				host_proc->ia_bits, host_proc->start_level, true);
		lz_flush_tlb_by_vmid(host_proc, 0, 0);
		host_proc->s2_pgd_phys = 0;
		if (host_proc->hcr & HCR_VM)
			lz_destroy_seq_table(host_proc);
	}
	host_proc->guest_proc = 0;
	host_proc->vtcr = 0;
	host_proc->vttbr = 0;
	host_proc->counters.seqtable_base = NULL;
	spin_unlock(&host_proc->proc_lock);

	spin_unlock(&host_proc->lowvisor_lock);

	return 0;
}

noinline static int lowvisor_init_nested_mmus(struct kvm_vcpu *vcpu, int nr_mmus)
{
	struct list_head *pos;
	lzproc_t *procs[MAX_LOWVISOR_NESTED_MMUS];
	int i;

	if (nr_mmus > MAX_LOWVISOR_NESTED_MMUS)
		nr_mmus = MAX_LOWVISOR_NESTED_MMUS;

	mmap_write_lock(current->mm);
	for (i = 0; i < nr_mmus; i++) {
		procs[i] = kzalloc(sizeof(lzproc_t), GFP_KERNEL);
		if (!procs[i]) {
			i -= 1;
			goto fail_alloc;
		}
		procs[i]->host_mm = current->mm;
		procs[i]->kvm = vcpu->kvm;
		procs[i]->hcr = LZ_HCR_VAL;
		atomic64_set(&procs[i]->nr_users, 0);
		atomic_set(&procs[i]->mn_start_end_balance, 0);
		atomic_set(&procs[i]->mn_gen, 0);
		spin_lock_init(&procs[i]->lowvisor_lock);
		spin_lock_init(&procs[i]->proc_lock);
		INIT_LIST_HEAD(&procs[i]->list_proc);
		lowvisor_register_notifier(procs[i]);
	}
	
	spin_lock(&big_lowvisor_lock);

	list_for_each(pos, &glzgprocs) {
		if (list_entry(pos, lzproc_t, list_proc)->kvm == vcpu->kvm) {
			spin_unlock(&big_lowvisor_lock);
			i = nr_mmus - 1;
			goto fail_alloc;
		}
	}

	for (i = 0; i < nr_mmus; i++)
		list_add(&procs[i]->list_proc, &glzgprocs);

	spin_unlock(&big_lowvisor_lock);
	mmap_write_unlock(current->mm);
	return 0;

fail_alloc:
	for (; i >= 0; i--) {
		mmu_notifier_unregister(&procs[i]->mn, procs[i]->host_mm);
		kfree(procs[i]);
	}
	mmap_write_unlock(current->mm);
	return -ENOMEM;
}

noinline static int lowvisor_init_shared_regs(struct kvm_vcpu *vcpu, int nr_sregs)
{
	struct list_head *pos;
	lzsregs_t **sregs;
	int i;

	if (nr_sregs > MAX_LOWVISOR_SHARED_REGS)
		nr_sregs = MAX_LOWVISOR_SHARED_REGS;

	sregs = kzalloc(sizeof(lzsregs_t *) * nr_sregs, GFP_KERNEL);
	if (!sregs)
		return -ENOMEM;

	mmap_write_lock(current->mm);
	for (i = 0; i < nr_sregs; i++) {
		sregs[i] = kzalloc(sizeof(lzsregs_t), GFP_KERNEL);
		if (!sregs[i]) {
			i -= 1;
			goto fail_alloc;
		}

		sregs[i]->kvm = vcpu->kvm;
		INIT_LIST_HEAD(&sregs[i]->list_sregs);
	}
	
	spin_lock(&big_lowvisor_lock);

	list_for_each(pos, &glzsregs) {
		if (list_entry(pos, lzsregs_t, list_sregs)->kvm == vcpu->kvm) {
			spin_unlock(&big_lowvisor_lock);
			i = nr_sregs - 1;
			goto fail_alloc;
		}
	}

	for (i = 0; i < nr_sregs; i++)
		list_add(&sregs[i]->list_sregs, &glzsregs);

	spin_unlock(&big_lowvisor_lock);
	mmap_write_unlock(current->mm);
	kfree(sregs);
	return 0;

fail_alloc:
	for (; i >= 0; i--)
		kfree(sregs[i]);
	mmap_write_unlock(current->mm);
	kfree(sregs);
	return -ENOMEM;
}

noinline static int lowvisor_kvm_handle_guest_abort(struct kvm_vcpu *vcpu, u64 hva, u64 hpfar, u64 esr)
{
	u64 far_el2, hpfar_el2, esr_el2;
	int rc;

	far_el2 = kvm_vcpu_get_hfar(vcpu);
	hpfar_el2 = vcpu->arch.fault.hpfar_el2;
	esr_el2 = kvm_vcpu_get_esr(vcpu);

	vcpu->arch.fault.far_el2 = hva;
	vcpu->arch.fault.hpfar_el2 = hpfar;
	vcpu->arch.fault.esr_el2 = esr;

	rc = IMPORTED(kvm_handle_guest_abort)(vcpu);

	dsb(ishst);
	__tlbi(alle1is);
	dsb(ish);
	isb();

	vcpu->arch.fault.far_el2 = far_el2;;
	vcpu->arch.fault.hpfar_el2 = hpfar_el2;
	vcpu->arch.fault.esr_el2 = esr_el2;

	if (rc == 1)
		return 0;
	return rc;
}

noinline static int lowvisor_setup_shared_regs(struct kvm_vcpu *vcpu, unsigned long regs)
{
	lzsregs_t *sregs;

	preempt_disable();
	sregs = find_sregs(vcpu->kvm, regs, true);
	preempt_enable();

	if (!sregs)
		return -EINVAL;
	return 0;
}

noinline static int lowvisor_clear_shared_regs(struct kvm_vcpu *vcpu, unsigned long regs)
{
	lzsregs_t *sregs;

	preempt_disable();
	sregs = find_sregs(vcpu->kvm, regs, false);
	preempt_enable();

	if (!sregs)
		return -EINVAL;

	sregs->gpa = 0;
	if (sregs->hva)
		put_page(virt_to_page(sregs->hva));
	sregs->hva = 0;

	return 0;
}

noinline static int lowvisor_set_pv_page(struct kvm_vcpu *vcpu, unsigned long gpa)
{
	int idx, rc;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	rc = find_pv_page(vcpu, gpa, true) ? 0 : -EINVAL;
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return rc;
}

static int preemptable_lowvisor_call(struct kvm_vcpu *vcpu)
{
	unsigned long rc;
	unsigned long func_id = vcpu_get_reg(vcpu, 0);
	unsigned long hvc_iss = (kvm_vcpu_get_esr(vcpu)) & ESR_ELx_ISS_MASK;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
	if (hvc_iss == LOWVISOR_CALL_VM_SWITCH_ISS) {
		/* Do a VMID update in the outer loop and re-exec HVC #1, not holding the mmap read lock */
		lzproc_t *host_proc;
		lzpage_t *pvp;
		preempt_disable();
		pvp = find_pv_page(vcpu, 0, false);
		if (pvp)
			host_proc = find_host_proc(vcpu->kvm, pvp->guest_proc_va, false);
		preempt_enable();
		if (!host_proc || !pvp) {
			vcpu_set_reg(vcpu, 0, ARM_EXCEPTION_IRQ);
			return 1;
		}
		lowvisor_ret_if_busy(host_proc, 1);
		lz_assign_vmid(host_proc, false);
		atomic64_dec(&host_proc->nr_users);
		*vcpu_pc(vcpu) -= 4;
		return 1;
	} else
#endif
	if (hvc_iss == LOWVISOR_CALL_FAULT_ISS) {
		vcpu_set_reg(vcpu, 0, lowvisor_handle_guest_abort(vcpu, false));
		return 1;
	} else if (func_id >= LOWVISOR_CALL_SETUP_STAGE2 && func_id <= LOWVISOR_CALL_SHARE_VCPU_PAGE) {
		/* If success, return 1 and use vcpu->x0 to pass the return value. */
		switch(func_id) {
			case LOWVISOR_CALL_SETUP_STAGE2:
				rc = lowvisor_setup_stage2(vcpu, vcpu_get_reg(vcpu, 1), vcpu_get_reg(vcpu, 2));
				break;
			case LOWVISOR_CALL_ZAP_STAGE2:
				rc = lowvisor_clear_flush_nested_pgtable(vcpu, vcpu_get_reg(vcpu, 1));
				break;
			case LOWVISOR_CALL_SETUP_PT_REGS:
				rc = lowvisor_setup_shared_regs(vcpu, vcpu_get_reg(vcpu, 1));
				break;
			case LOWVISOR_CALL_ZAP_PT_REGS:// FIXME: notifier and re-get page
				rc = lowvisor_clear_shared_regs(vcpu, vcpu_get_reg(vcpu, 1));
				break;
			case LOWVISOR_CALL_SETUP_NESTED_MMUS:
				rc = lowvisor_init_nested_mmus(vcpu, vcpu_get_reg(vcpu, 1));
				break;
			case LOWVISOR_CALL_SETUP_SHARED_REGS:
				rc = lowvisor_init_shared_regs(vcpu, vcpu_get_reg(vcpu, 1));
				break;
			case LOWVISOR_CALL_KVM_GUEST_ABORT:
				rc = lowvisor_kvm_handle_guest_abort(vcpu, vcpu_get_reg(vcpu, 1),
						vcpu_get_reg(vcpu, 2), vcpu_get_reg(vcpu, 3));
				break;
			default:	/* LOWVISOR_CALL_SHARE_VCPU_PAGE */
				rc = lowvisor_set_pv_page(vcpu, vcpu_get_reg(vcpu, 1));
		}

		vcpu_set_reg(vcpu, 0, rc);
		return 1;
	}

	return original_handle_hvc(vcpu);
}

int lz_register_lowvisor(void)
{
	exit_handle_fn *arm_handlers = (exit_handle_fn *)(IMPORTED(arm_exit_handlers));
	struct file_operations *vm_fops = IMPORTED(kvm_vm_fops);
	struct file_operations *vcpu_fops = IMPORTED(kvm_vcpu_fops);

	lowvisor_detect_feat = 0 & LOWVISOR_DETECT_GICV_REG;	// TODO: How to detect half-emulated GICV2 or V3 for the VM
	write_sysreg(read_sysreg(mdcr_el2) | MDCR_EL2_TTRF, mdcr_el2);
	lowvisor_detect_feat |= (read_sysreg(mdcr_el2) & MDCR_EL2_TTRF) ? LOWVISOR_DETECT_FEAT_TRF : 0;
	printk(KERN_INFO "lightzone: Lowvisor %lx features detected\n", (unsigned long)lowvisor_detect_feat);

	if (IMPORTED(lightzone_lowvisor_early_handler))
		*IMPORTED(lightzone_lowvisor_early_handler) = lowvisor_prehandler;
	else {
		exit_handler_fn *inner_handlers = (exit_handler_fn *)(IMPORTED(hyp_exit_handlers));
		if (change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_HVC64])), true)) 
			goto cannot_change_handler;
		inner_handlers[ESR_ELx_EC_HVC64] = fast_lowvisor_call;
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_HVC64])), false);
		original_sysreg_fault = inner_handlers[ESR_ELx_EC_SYS64];
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_SYS64])), true);
		inner_handlers[ESR_ELx_EC_SYS64] = lowvisor_prehandle_sysreg_fault;
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_SYS64])), false);
	}

	/* Modify the outer-loop handler. */
	original_handle_hvc = arm_handlers[ESR_ELx_EC_HVC64];
	if (change_kernel_pgtable_perm((unsigned long)(&(arm_handlers[ESR_ELx_EC_HVC64])), true)) {
cannot_change_handler:
		printk(KERN_ERR "lightzone: Cannot write the outer handler for permission violation\n");
		return -EINVAL;
	}
	arm_handlers[ESR_ELx_EC_HVC64] = preemptable_lowvisor_call;
	change_kernel_pgtable_perm((unsigned long)(&(arm_handlers[ESR_ELx_EC_HVC64])), false);

	/* Modify the vm_fops->release. */
	original_kvm_vm_release = vm_fops->release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vm_fops->release)), true);
#endif
	vm_fops->release = lz_kvm_vm_release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vm_fops->release)), false);
#endif

	/* Modify the vm_fops->release. */
	original_kvm_vcpu_release = vcpu_fops->release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vcpu_fops->release)), true);
#endif
	vcpu_fops->release = lz_kvm_vcpu_release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vcpu_fops->release)), false);
#endif

	if (IMPORTED(lightzone_lowvisor_ops_valid)) {
		*IMPORTED(lightzone_lowvisor_ops_wp) = lz_nested_s2_wp;
		*IMPORTED(lightzone_lowvisor_ops_flush) = lz_nested_s2_flush;
		*IMPORTED(lightzone_lowvisor_ops_clear) = lz_nested_s2_clear;
		*IMPORTED(lightzone_lowvisor_ops_valid) = true;
	}

	spin_lock_init(&big_lowvisor_lock);

	/* All is WELL!!! */
	printk(KERN_INFO "lightzone: Lowvisor installed\n");
	return 0;
}

void lz_unregister_lowvisor(void)
{
	exit_handle_fn *arm_handlers = (exit_handle_fn *)(IMPORTED(arm_exit_handlers));
	struct file_operations *vm_fops = IMPORTED(kvm_vm_fops);
	struct file_operations *vcpu_fops = IMPORTED(kvm_vcpu_fops);

	if (IMPORTED(lightzone_lowvisor_early_handler))
		*IMPORTED(lightzone_lowvisor_early_handler) = NULL;
	else {
		exit_handler_fn *inner_handlers = (exit_handler_fn *)(IMPORTED(hyp_exit_handlers));
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_HVC64])), true);
		inner_handlers[ESR_ELx_EC_HVC64] = NULL;
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_HVC64])), false);
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_SYS64])), true);
		inner_handlers[ESR_ELx_EC_SYS64] = original_sysreg_fault;
		change_kernel_pgtable_perm((unsigned long)(&(inner_handlers[ESR_ELx_EC_SYS64])), false);
	}

	change_kernel_pgtable_perm((unsigned long)(&(arm_handlers[ESR_ELx_EC_HVC64])), true);
	arm_handlers[ESR_ELx_EC_HVC64] = original_handle_hvc;
	change_kernel_pgtable_perm((unsigned long)(&(arm_handlers[ESR_ELx_EC_HVC64])), false);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vm_fops->release)), true);
#endif
	vm_fops->release = original_kvm_vm_release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vm_fops->release)), false);
	change_kernel_pgtable_perm((unsigned long)(&(vcpu_fops->release)), true);
#endif
	vcpu_fops->release = original_kvm_vcpu_release;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
#else
	change_kernel_pgtable_perm((unsigned long)(&(vcpu_fops->release)), false);
#endif

	if (IMPORTED(lightzone_lowvisor_ops_valid)) {
		*IMPORTED(lightzone_lowvisor_ops_valid) = false;
		*IMPORTED(lightzone_lowvisor_ops_wp) = NULL;
		*IMPORTED(lightzone_lowvisor_ops_flush) = NULL;
		*IMPORTED(lightzone_lowvisor_ops_clear) = NULL;
	}
}

#endif