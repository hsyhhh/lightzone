#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_arm.h>
#include <asm/cpufeature.h>
#include <asm/esr.h>
#include <asm/syscall.h>

#include "lzcpu.h"
#include "lzarm.h"
#include "pt.h"
#include "npt.h"
#include "hwdefs.h"
#include "copied.h"
#include "paravirt.h"
#include "nohammer.h"

extern struct list_head glzcpus;
extern struct list_head glzprocs;
extern struct rw_semaphore big_lz_lock;
extern char *all_per_vcpu_pages;

DEFINE_PER_CPU(lzctxt_host_t, lz_host_ctxt);
DEFINE_PER_CPU(struct pt_regs *, lz_guest_ctxt);
static DEFINE_PER_CPU(lzcpu_t *, scheduled_lzcpu);

extern u64 host_init_hcr_el2;
extern u64 host_init_cptr_el2;
extern u64 host_init_cnthctl_el2;
extern u64 host_init_mdcr_el2;
extern syscall_fn_t lz_syscall_tbl[__NR_syscalls];

inline static int lz_do_syscall(lzcpu_t *lzcpu)
{
	unsigned long x0;
	struct pt_regs *regs;
	syscall_fn_t syscall_fn;

	regs = current_pt_regs();
	if (regs->regs[8] < __NR_syscalls) {
		regs->syscallno = (int)regs->regs[8];
		regs->orig_x0 = (unsigned long)lzcpu;
		syscall_fn = lz_syscall_tbl[array_index_nospec(regs->regs[8], __NR_syscalls)];
		x0 = syscall_fn(regs);
		regs->orig_x0 = regs->regs[0];
		regs->regs[0] = x0;
	} else
		regs->regs[0] = -ENOSYS;
	return 0;
}

static void lzcpu_load(lzcpu_t *lzcpu, unsigned long sp, lzpage_t **ppvp)
{
	lzpage_t *pvp;

	if (lzcpu->first_sched_in)
		*ppvp = get_pv_page(smp_processor_id());
	pvp = *ppvp;

	if (lzcpu->first_sched_in) {
		lzcpu->first_sched_in = false;
		/* We ignore vgic and vtimer as a normal process. */
		/* Load some system registers to EL1 LightZone process. */
		PV_write_sysreg_ho(PV_read_sysreg_ho(csselr_el1),				csselr_el1);
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(sctlr_el1),			SYS_SCTLR);	/* sys ctrl */
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(afsr0_el1),			SYS_AFSR0);
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(afsr1_el1),			SYS_AFSR1);
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(contextidr_el1),		SYS_CONTEXTIDR);
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(amair_el1),			SYS_AMAIR);
		PV_write_sysreg_ho(PV_read_sysreg_ho(tpidr_el1),				tpidr_el1);			
		PV_write_sysreg_el1_ho(PV_read_sysreg_ho(mair_el1),				SYS_MAIR);
	
		PV_write_lzproc_go(lzcpu->proc, 						pvp);
		PV_write_sysreg_ho(read_sysreg(mpidr_el1),				vmpidr_el2);
		PV_write_sysreg_ho(read_sysreg(midr_el1),				vpidr_el2);
		PV_write_sysreg_ho(LZ_MDCR_SET_VAL,						mdcr_el2);
		PV_write_sysreg_el1((read_sysreg(tcr_el1) & ~TCR_A1 & ~TCR_HA & ~TCR_HD)
														,	PVSYS_TCR, pvp);	/* TTBR0_EL1 for asid */
		PV_write_sysreg_ho(LZ_CPTR_SET_VAL | CPACR_EL1_FPEN_EL1EN | CPACR_EL1_FPEN_EL0EN, cpacr_el1);
		PV_write_sysreg_el1(LZ_CPTR_SET_VAL | CPACR_EL1_FPEN_EL1EN | CPACR_EL1_FPEN_EL0EN,
							PVSYS_CPACR, pvp);		/* No SVE in guest, ONLY by bin inspection */
		PV_write_sysreg_el1(0x0,							PVSYS_CNTKCTL, pvp);	/* No virtual counter */
		PV_write_sysreg_el1(lzcpu->proc->ttbr1,				PVSYS_TTBR1, pvp);
		PV_write_sysreg_el1(lzcpu->proc->vbar,				PVSYS_VBAR, pvp);
		PV_write_sysreg_el1(lzcpu->esr_el1,					PVSYS_ESR, pvp);
		PV_write_sysreg_el1(lzcpu->far_el1,					PVSYS_FAR, pvp);
		PV_write_sysreg_el1(lzcpu->spsr_el1,				PVSYS_SPSR, pvp);
		if (lzcpu->proc->hcr & HCR_VM)
			PV_write_sysreg_ho(lzcpu->proc->vtcr, 			vtcr_el2);
	}

	/* These registers may be modified by LightZone kernel module at a low frequency. */
	PV_write_sysreg(sp,								sp_el1, pvp);
	PV_write_sysreg_el1(0x0,						PVSYS_ELR, pvp);
	if (PV_read_sysreg_el1(PVSYS_TTBR0, pvp) != lzcpu->ttbr0)
		PV_write_sysreg_el1(lzcpu->ttbr0,			PVSYS_TTBR0, pvp);

	isb();
}

static void lz_sched_in(struct preempt_notifier *pn, int cpu)
{
	lzcpu_t *lzcpu = container_of_safe(pn, lzcpu_t, pn);

	this_cpu_write(scheduled_lzcpu, lzcpu);
	lzcpu->cpu = cpu;
	lzcpu->first_sched_in = true;
}

static void lz_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	lzcpu_t *lzcpu = container_of_safe(pn, lzcpu_t, pn);

	lzcpu->first_sched_in = false;
	lzcpu->cpu = -1;
	this_cpu_write(scheduled_lzcpu, NULL);
	PV_write_sysreg_ho(host_init_mdcr_el2, mdcr_el2);
#ifdef TGE_OPT_EL2
	PV_write_sysreg_ho(LZ_HCR_VAL | HCR_TGE, hcr_el2);
	isb();
#endif
}

static struct preempt_ops lz_preempt_ops = {
	.sched_in = lz_sched_in,
	.sched_out = lz_sched_out,
};

static lzproc_t *get_lzproc(struct task_struct *tsk)
{
	struct list_head *pos;
	lzproc_t *tmp;
	list_for_each(pos, &glzprocs) {
		tmp = list_entry(pos, lzproc_t, list_proc);
		if (tmp->host_mm == tsk->mm)
			return tmp;
	}
	return NULL;	
}

static void init_lzcpu_regs(lzcpu_t *lzcpu, lzconf_t *lzconf, 
				int from, lzconf_el1_sys_t *lzconf_el1_sys)
{
	lzpgt_t *pgt;
	struct pt_regs *regs = current_pt_regs();
	
	lzcpu->esr_el1 = read_sysreg(esr_el1);
	lzcpu->far_el1 = read_sysreg(far_el1);

	if (from == LZ_ENTRY_FROM_USER) {
		lzcpu->elr_el1 = read_sysreg(elr_el1);
		lzcpu->spsr_el1 = read_sysreg(spsr_el1) & (~PSR_UAO_BIT);
	} else {
		lzcpu->elr_el1 = lzconf_el1_sys->elr_el1;
		lzcpu->spsr_el1 = lzconf_el1_sys->spsr_el1 & (~PSR_UAO_BIT);
	}

	/* Virt memory and VBAR_EL1. */
	if (!list_empty(&lzcpu->proc->list_s1_mmu)) {
		pgt = list_entry(lzcpu->proc->list_s1_mmu.next, lzpgt_t, list_s1_mmu);
		lzcpu->ttbr0 = (pgt->s1_pgd_seq | (pgt->s1_asid << USER_ASID_BIT));
	}

	regs->regs[0] = 0;
}

static void lzproc_destroy(lzproc_t *lzproc)
{
	lzrange_t *range;

	while (!RB_EMPTY_ROOT(&lzproc->lzrange)) {
		range = rb_entry(lzproc->lzrange.rb_node, lzrange_t, node);
		rb_erase(&range->node, &lzproc->lzrange);
		kfree(range);
	}
	/* Unregister, free stage 1&2 page tables. */
	lz_free_stages(lzproc);
	kfree(lzproc);
}

void lzcpu_destroy(lzcpu_t *lzcpu)
{
	int nr_users;
	lzproc_t *lzproc = lzcpu->proc;

	PV_zap_lzcpu_pt_regs(lzcpu->pt_regs_pa);
	preempt_disable();
#ifdef TGE_OPT_EL2
	/*
	 * Also in do_bad, do_translation_fault, do_page_fault,
	 * do_sea, do_tag_check_fault, do_alignment_fault
	 */
	PV_write_sysreg_ho(LZ_HCR_VAL | HCR_TGE, hcr_el2);
	isb();
#endif
	lzcpu->cpu = -1;
	this_cpu_write(scheduled_lzcpu, NULL);
	preempt_notifier_unregister(&lzcpu->pn);
	preempt_enable();
	preempt_notifier_dec();
	if (lzproc) {
		down_write(&big_lz_lock);
		nr_users = atomic64_dec_return(&lzproc->nr_users);
		spin_lock(&lzproc->proc_lock);
		list_del(&lzcpu->list_cpu);	/* Proc list */
		spin_unlock(&lzproc->proc_lock);
		if (!nr_users) {
			list_del(&lzproc->list_proc);
			up_write(&big_lz_lock);
			lzproc_destroy(lzproc);
		} else
			up_write(&big_lz_lock);
	}
	
	/* Free the CPU itself after deleted from list, no race. */
	kfree(lzcpu);		
}

static bool lzconf_sanitized(lzconf_t *lzconf)
{
	if (lzconf->user_vbar & 0xffff0000000007ffUL)
		return false;
	if ((lzconf->ttbr0_tab_start & (~PAGE_MASK)) || (lzconf->ttbr0_tab_end & (~PAGE_MASK)) ||
			lzconf->ttbr0_tab_start >= lzconf->ttbr0_tab_end ||
			lzconf->ttbr0_tab_end - lzconf->ttbr0_tab_start > CALL_GATE_START_EL1 - TTBR0_TAB_START_EL1)
		return false;
	if ((lzconf->per_gate_start & (~PAGE_MASK)) || (lzconf->per_gate_end & (~PAGE_MASK)) ||
			lzconf->per_gate_start >= lzconf->per_gate_end ||
			lzconf->per_gate_end - lzconf->per_gate_start > 8 * PAGE_SIZE)
		return false;
	if ((lzconf->call_gate_start & (~PAGE_MASK)) || (lzconf->call_gate_end & (~PAGE_MASK)) ||
			lzconf->call_gate_start >= lzconf->call_gate_end ||
			lzconf->per_gate_end - lzconf->per_gate_start > PER_GATE_ZONE_RET_START_EL1 - CALL_GATE_START_EL1)
		return false;
	return true;
}

int lz_gate_tab_init(lzproc_t *proc)
{
	int nr, rc;
	unsigned long start = proc->per_gate_start;
	unsigned long end = proc->per_gate_end;
	
	if (!(proc->hcr & HCR_VM))
		return 0;
	
	nr = (end - start) / PAGE_SIZE;
	proc->per_gate_pages = (struct page **)kzalloc(nr * sizeof(struct page *), GFP_KERNEL);
	if (!proc->per_gate_pages)
		return -ENOMEM;
	rc = get_user_pages(start, nr, FOLL_FORCE, proc->per_gate_pages, NULL);
	if (rc != nr)
		return -EINVAL;
	return 0;
}

lzcpu_t *lzcpu_create(lzconf_t *lzconf, int from, lzconf_el1_sys_t *lzconf_el1_sys)
{
	int rc;
	lzcpu_t *lzcpu;
	lzproc_t *lzproc;

	mmap_write_lock(current->mm);
	down_write(&big_lz_lock);
	lzcpu = get_current_lzcpu();
	lzproc = get_lzproc(current);

	if (lzcpu)
		goto fail_cpu;	/* No re-entering LightZone */

	lzcpu = kzalloc(sizeof(lzcpu_t), GFP_KERNEL);
	if (!lzcpu)
		goto fail_cpu;
	if (PV_init_lzcpu_pt_regs(current_pt_regs(), lzcpu)) {
		printk(KERN_ERR "lightzone: Out of shared pt_regs\n");
		goto fail_proc;
	}
	INIT_LIST_HEAD(&lzcpu->list_cpu);

	if (!lzproc) {
		if (!lzconf_sanitized(lzconf))
			goto fail_proc;
		lzproc = kzalloc(sizeof(lzproc_t), GFP_KERNEL);
		if (!lzproc)
			goto fail_proc;
		lzproc->host_mm = current->mm;
		lzproc->hcr = LZ_HCR_VAL;
		if (lzconf->scalable)
			lzproc->hcr |= HCR_VM;
		else
			lzproc->hcr |= HCR_TVM;
		atomic64_set(&lzproc->nr_users, 0);
		atomic_set(&lzproc->mn_start_end_balance, 0);
		atomic_set(&lzproc->mn_gen, 0);
		spin_lock_init(&lzproc->proc_lock);
		INIT_LIST_HEAD(&lzproc->list_proc);
		INIT_LIST_HEAD(&lzproc->list_s1_mmu);
		rc = PV_lz_setup_stage2(lzproc);
		if (rc)
			goto fail_proc;
		spin_lock(&lzproc->proc_lock);
		if (!(rc = lz_init_seqtable_locked(lzproc)))
			rc = PV_lz_init_stage2_mmu_locked(lzproc);
		spin_unlock(&lzproc->proc_lock);
		if (rc)
			goto fail_proc;
		rc = PV_lz_register_notifier(lzproc);
		if (rc)
			goto fail_stage2;
		/* set these before init stage 1 mmu */
		lzproc->ttbr0_tab_start = lzconf->ttbr0_tab_start;
		lzproc->ttbr0_tab_end = lzconf->ttbr0_tab_end;
		lzproc->per_gate_start = lzconf->per_gate_start;
		lzproc->per_gate_end = lzconf->per_gate_end;
		lzproc->call_gate_start = lzconf->call_gate_start;
		lzproc->call_gate_end = lzconf->call_gate_end;
		lzproc->vbar = lzconf->user_vbar;
		rc = lz_gate_tab_init(lzproc);
		if (rc)
			goto fail_stage2;
		/* list_s1_mmu added if success */
		rc = lz_init_stage1_mmu(lzproc, 0, NULL);
		if (rc)
			goto fail_stage2;
		lzproc->lzrange = RB_ROOT;
		lzproc->ttbr1 = lzproc->default_ttbr0;
		list_add(&lzproc->list_proc, &glzprocs);
	}

	/**
	 * LightZone boots from a process rather than a fixed initial
	 * vm state. Hence, the process must continue as if it is invoking
	 * a normal syscall rather than no-return call. Also, we assume
	 * the kernel does not change the values of FPSIMD registers so no
	 * such register switch is needed in LightZone.
	 */
	list_add(&lzcpu->list_cpu, &glzcpus);
	lzcpu->proc = lzproc;
	lzcpu->cpu = -1;
	lzcpu->first_sched_in = true;
	atomic64_inc(&lzproc->nr_users);
	up_write(&big_lz_lock);
	mmap_write_unlock(current->mm);
	preempt_notifier_inc();
	preempt_notifier_init(&lzcpu->pn, &lz_preempt_ops);
	init_lzcpu_regs(lzcpu, lzconf, from, lzconf_el1_sys);
	return lzcpu;

fail_stage2:
	lz_free_stages(lzproc);	/* unregister notifier and destroy both stages */
fail_proc:
	kfree(lzcpu);
fail_cpu:
	up_write(&big_lz_lock);
	mmap_write_unlock(current->mm);
	return NULL;
}

static void lz_deactivate_traps(lzcpu_t *lzcpu)
{
#ifdef TGE_OPT_EL2
#else
	PV_isb_ho();
	PV_write_sysreg_ho(lzcpu->proc->hcr | HCR_TGE, hcr_el2);
#endif

	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL2/EL0 translation regime used by
	 * the host.
	 */
	PV_isb_ho();

	/* write_sysreg(host_init_cnthctl_el2, cnthctl_el2); */
	PV_write_sysreg_ho(host_init_cptr_el2, cpacr_el1);
	PV_write_sysreg_ho((char *)IMPORTED(vectors), vbar_el1);
}

/* 
 * __kvm_vcpu_run_vhe, in the irq disabled, non-preemption context. 
 * VHE: Host and guest must save mdscr_el1 and sp_el0 (and the PC and
 * pstate, which are handled as part of the el2 return state) on every
 * switch (sp_el0 is being dealt with in the assembly code).
 * tpidr_el0 and tpidrro_el0 only need to be switched when going
 * to host userspace or a different VCPU.  EL1 registers only need to be
 * switched when potentially going to run a different VCPU.  The latter two
 * classes are handled as part of kvm_arch_vcpu_load and kvm_arch_vcpu_put.
 */
extern char lz_hyp_vector[];
extern unsigned long lz_vm_entry(struct pt_regs *regs);

static unsigned long lzcpu_enter_guest_vhe(lzcpu_t *lzcpu, struct pt_regs *regs, lzpage_t *pvp)
{
#if defined(CONFIG_ARM64_MTE) || defined(CONFIG_ARM64_PTR_AUTH) || defined(CONFIG_ARM64_RAS_EXTN)
#warning "Please switch context for MTE, RAS and PA in LightZone switch!"
#endif
	unsigned long exit_code, val;

	/*
	 * ARM erratum 1165522 requires us to configure both stage 1 and
	 * stage 2 translation for the guest context before we clear
	 * HCR_EL2.TGE.
	 *
	 * We have already configured the guest's stage 1 translation in
	 * lzcpu_load above.  We must now configure stage 2 translation, and
	 * activate traps to clear HCR_EL2.TGE (among other things).
	 */
	if (unlikely(PV_read_sysreg_ho(vttbr_el2) != lzcpu->proc->vttbr))
		PV_write_sysreg_ho(lzcpu->proc->vttbr, vttbr_el2);

	/*************** Activate traps. ***************/
#ifdef TGE_OPT_EL2
	if (PV_read_sysreg_ho(hcr_el2) & HCR_TGE)
#endif
	{
		PV_isb_ho();
		PV_write_sysreg_ho(lzcpu->proc->hcr, hcr_el2);
	}
	PV_isb_ho();

	/* Set VBAR of hypercall, note that it is different from KVM's handler. */
	PV_write_sysreg_for_kernel((unsigned long)lz_hyp_vector, vbar_el1, pvp);

	PV_write_sysreg_el2(regs->pc, PVSYS_ELR, pvp);
	PV_write_sysreg_el2(regs->pstate, PVSYS_SPSR, pvp);

	exit_code = PV_lz_vm_entry(regs, lzcpu);
	this_cpu_write(lz_guest_ctxt, NULL);

	/* 
	 * Restore LightZone process in-VM context.
	 */
	lzcpu->esr = PV_read_sysreg_el2(PVSYS_ESR, pvp);
	regs->pc   = PV_read_sysreg_el2(PVSYS_ELR, pvp);
	/*
	 * The HPFAR can be invalid if the stage 2 fault did not
	 * happen during a stage 1 page table walk (the ESR_EL2.S1PTW
	 * bit is clear) and one of the two following cases are true:
	 *   1. The fault was due to a permission fault
	 *   2. The processor carries errata 834220
	 *
	 * Therefore, for all non S1PTW faults where we either have a
	 * permission fault or the errata workaround is enabled, we
	 * resolve the IPA using the AT instruction.
	 */
	if (ESR_ELx_EC(lzcpu->esr) == ESR_ELx_EC_IABT_LOW ||
			ESR_ELx_EC(lzcpu->esr) == ESR_ELx_EC_DABT_LOW) {
		lzcpu->far = PV_read_sysreg_el2(PVSYS_FAR, pvp);
#ifdef RUN_ON_VHE_HOST
		if (!(lzcpu->esr & ESR_ELx_S1PTW) &&
			(cpus_have_final_cap(ARM64_WORKAROUND_834220) ||
			(lzcpu->esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
			if (!__kvm_at("s1e1r", (lzcpu->far)))
				lzcpu->hpfar = PAR_TO_HPFAR(read_sysreg_par());
			else
				exit_code = ARM_EXCEPTION_IL;
		} else
#endif
			lzcpu->hpfar = PV_read_sysreg(hpfar_el2, pvp);
	} 
	lzcpu->esr_el1 = PV_read_sysreg_el1(PVSYS_ESR, pvp);
	lzcpu->far_el1 = PV_read_sysreg_el1(PVSYS_FAR, pvp);
	val = PV_read_sysreg_el1(PVSYS_ELR, pvp);
	if (val)
		lzcpu->elr_el1 = val;
	lzcpu->spsr_el1 = PV_read_sysreg_el1(PVSYS_SPSR, pvp);
	regs->sp = PV_read_sysreg(sp_el1, pvp);
	regs->pstate = PV_read_sysreg_el2(PVSYS_SPSR, pvp);
	lzcpu->ttbr0 = PV_read_sysreg_el1(PVSYS_TTBR0, pvp);

	/************** Deactivate traps. **************/
	lz_deactivate_traps(lzcpu);

	return exit_code;
}

static int lzcpu_enter_guest(lzcpu_t *lzcpu, struct pt_regs *regs, lzpage_t *pvp)
{
	int ret;

	/* In fact, our Kconfig does not support priority masking. */
	local_daif_mask();

	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 *
	 * local_daif_mask() already sets GIC_PRIO_PSR_I_SET, we just need a
	 * dsb to ensure the redistributor is forwards EL2 IRQs to the CPU.
	 */
	if (system_uses_irq_prio_masking())
		pmr_sync();

	ret = lzcpu_enter_guest_vhe(lzcpu, regs, pvp);	/* __kvm_vcpu_run_vhe */

	/*
	 * local_daif_restore() takes care to properly restore PSTATE.DAIF
	 * and the GIC PMR if the host is using IRQ priorities.
	 * IRQ and FIQ are restored in local_irq_enable().
	 */
	local_daif_restore(PSR_I_BIT | PSR_F_BIT);

	/*
	 * When we exit from the guest we change a number of CPU configuration
	 * parameters, such as traps.  Make sure these changes take effect
	 * before running the host or additional guests.
	 */
	isb();

	return ret;
}

inline static int lz_handle_trap_exceptions(lzcpu_t *lzcpu, struct pt_regs *regs)
{
	unsigned long ipa;
	u8 esr_el1_ec;
	u64 esr = lzcpu->esr;
	u8 esr_ec = ESR_ELx_EC(esr);
	u16 esr_imm = esr & 0xffff;
	bool s1ptw = esr & ESR_ELx_S1PTW;

	/* [0 ... ESR_ELx_EC_MAX],
	 * [ESR_ELx_EC_WFx],
	 * [ESR_ELx_EC_CP15_32],
	 * [ESR_ELx_EC_CP15_64],
	 * [ESR_ELx_EC_CP14_MR],
	 * [ESR_ELx_EC_CP14_LS],
	 * [ESR_ELx_EC_CP10_ID],
	 * [ESR_ELx_EC_CP14_64],
	 * [ESR_ELx_EC_HVC32],
	 * [ESR_ELx_EC_SMC32],
	 * [ESR_ELx_EC_HVC64],
	 * [ESR_ELx_EC_SMC64],
	 * [ESR_ELx_EC_SYS64],
	 * [ESR_ELx_EC_SVE],
	 * [ESR_ELx_EC_IABT_LOW],
	 * [ESR_ELx_EC_DABT_LOW],
	 * [ESR_ELx_EC_SOFTSTP_LOW],
	 * [ESR_ELx_EC_WATCHPT_LOW],
	 * [ESR_ELx_EC_BREAKPT_LOW],
	 * [ESR_ELx_EC_BKPT32],
	 * [ESR_ELx_EC_BRK64],
	 * [ESR_ELx_EC_FP_ASIMD],
	 * [ESR_ELx_EC_PAC],
	 */
	switch (esr_ec) {
	case ESR_ELx_EC_HVC64:
		regs->pc = lzcpu->elr_el1;
		regs->pstate = lzcpu->spsr_el1;
		esr_el1_ec = ESR_ELx_EC(lzcpu->esr_el1);
		if (esr_imm == 6 || esr_imm == 7)
			return 0;
		if (esr_imm) {
			printk(KERN_ERR "lightzone: EL1 met unhandled fault ec %x, hvc #%d\n", esr_el1_ec, esr_imm);
			return -EFAULT;
		}
		switch (esr_el1_ec) {
		case ESR_ELx_EC_SVC64:
			return lz_do_syscall(lzcpu);
		case ESR_ELx_EC_IABT_CUR:
		case ESR_ELx_EC_DABT_CUR:
			return lz_user_mem_abort(lzcpu, (lzcpu->hpfar & HPFAR_MASK) << 8, MMU_STAGE1);
		default:
			printk(KERN_ERR "lightzone: Unsupported EL1 trap type from HVC: %d\n",
			      esr_el1_ec);
			return -EFAULT;
		}
	case ESR_ELx_EC_FP_ASIMD:
		asm volatile("fmov	x0, d16\n\t" ::: "x0", "memory");
		return 0;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		if (lzcpu->proc->hcr & HCR_VM) {
			ipa = (lzcpu->hpfar & HPFAR_MASK) << 8;
			if (s1ptw)
				return lz_kernel_mem_abort(lzcpu, ipa);
			return lz_user_mem_abort(lzcpu, ipa, MMU_STAGE2);
		} else {
			int rc = PV_trig_stage2(lzcpu->far, lzcpu->hpfar, lzcpu->esr);
			PV_lz_flush_tlb_by_vmid_s1(lzcpu->proc, 0);
			return rc;
		}
	default:
		printk(KERN_ERR "lightzone: Unsupported trap type: %d\n",
			      esr_ec);
		return -EFAULT;
	}
}

inline static int lz_handle_exit(lzcpu_t *lzcpu, int exception_index)
{
	struct pt_regs *regs = current_pt_regs();
	exception_index = ARM_EXCEPTION_CODE(exception_index);
	regs->syscallno = NO_SYSCALL;
	regs->orig_x0 = regs->regs[0];

	switch (exception_index) {
	case ARM_EXCEPTION_IRQ:
		if (atomic_cmpxchg(&lzcpu->proc->vbar_unmapped, 1, 0)) {
			/* Declare before really map it! */
			int rc;
			unsigned long ipa, seqpa;
			struct list_head *pos;
			lzpgt_t *tmp;
			lzproc_t *lzproc = lzcpu->proc;

			mmap_read_lock(current->mm);

			list_for_each(pos, &lzproc->list_s1_mmu) {
				tmp = list_entry(pos, lzpgt_t, list_s1_mmu);
				seqpa = ipa = 0;
				rc = get_user_pages_handle_fault(lzcpu, __va(tmp->s1_pgd_phys), lzproc->vbar, &seqpa, &ipa, LZ_PF_INIT, 0);
				if (rc >= 0 && (lzproc->hcr & HCR_VM))
					if ((rc = PV_handle_nested_page_fault(lzproc, (pgd_t *)(__va(lzproc->s2_pgd_phys)), seqpa, ipa,
						(rc & LZ_PF_LEV_MASK) >> LZ_PF_LEV_SHIFT, LZ_PF_INIT | rc)))
						printk(KERN_ERR "lightzone: Failed to handle IPA fault\n");
				spin_unlock(&lzproc->proc_lock);

				if (rc < 0)
					break;
			}

			mmap_read_unlock(current->mm);
			printk(KERN_INFO "lightzone: VBar remapped eagerly for every page tables %d\n", rc);
			if (rc < 0)
				return -EINVAL;
		}
		return 0;	/* handled earlier */
	case ARM_EXCEPTION_EL1_SERROR:
		printk(KERN_ERR "lightzone: Unsupported exception type SError\n");
		return -EINVAL;
	case ARM_EXCEPTION_TRAP:
		return lz_handle_trap_exceptions(lzcpu, regs);
	default:
		printk(KERN_ERR "lightzone: Unsupported exception type: %d\n",
			      exception_index);
		return -EINVAL;
	}
}

/* Mimic kvm_arm_vcpu_enter_exit. */
static int noinstr lzcpu_enter_exit(lzcpu_t *lzcpu, struct pt_regs *regs, lzpage_t *pvp)
{
	return lzcpu_enter_guest(lzcpu, regs, pvp);	/* __kvm_vcpu_run */
}

static bool check_add_asid(u64 *pstate, u64 asid)
{
	if (*pstate & ((-1UL) << SYS_SPSR_RES0_USED_SHIFT))
		return false;
	*pstate |= (asid << SYS_SPSR_RES0_USED_SHIFT);
	return true;
}

/* Mimic kvm_arch_vcpu_ioctl_run. */
int lzcpu_run(lzcpu_t *lzcpu)
{
	int cpu;
	int rc;
	unsigned long flags;
	struct pt_regs *regs;
	lzpage_t *pvp = NULL;
	extern void fpsimd_restore_current_state(void);

	preempt_notifier_register(&lzcpu->pn);

	/* Never leave LightZone unless signals. */
	while (1) {
		PV_lz_assign_vmid(lzcpu->proc, false);

		cpu = get_cpu();
		this_cpu_write(scheduled_lzcpu, lzcpu);
		lzcpu->cpu = cpu;
		local_irq_disable();
		regs = current_pt_regs();

		/************************************************************
		 * ********** prepare exit to LightZone user mode ***********
		 ************************************************************/
		flags = current_thread_info()->flags;

		if (PV_NEED_NEW_VMID_GENERATION()) {
			local_irq_enable();
			put_cpu();
			continue;
		}

		if (flags & _TIF_NEED_RESCHED) {
			local_irq_enable();
			put_cpu();
			cond_resched();
			current_thread_info()->flags &= ~_TIF_NEED_RESCHED;
			continue;
		}

		if (flags & (_TIF_SIGPENDING | _TIF_NOTIFY_RESUME | _TIF_FOREIGN_FPSTATE | _TIF_UPROBE)) {
			local_irq_enable();
			put_cpu();

			if (flags & _TIF_UPROBE) {
				printk(KERN_ERR "lightzone: Unsupported debug feature UPROBE met\n");
				break;
			}

			if (flags & _TIF_SIGPENDING) {
				/* 
				 * Before handle signals, we must handle some terminations.
				 * In get_signal(), the entry "fatal" means no return. How-
				 * ever, prechecking this in here faces the race condition,
				 * hence, we copy kernel/signal/signal.c/get_signal() in
				 * copied.c and add only one line before do_group_exit. That
				 * is, lzcpu_destroy(lzcpu). Also note that PF_IO_WORKER
				 * threads are never running in LightZone.
				 */
				if (!check_add_asid(&regs->pstate, (lzcpu->ttbr0 & TTBR_ASID_MASK) >> USER_ASID_BIT))
					printk(KERN_ERR "lightzone: PSTATE[63: 48] is not unused, see struct sigcontext\n");
				regs->pstate = (regs->pstate & (~PSR_MODE_MASK)) | PSR_MODE_EL0t;
				IMPORTED(do_signal)(regs, (void *)lzcpu);
				regs->pstate = (regs->pstate & (~PSR_MODE_MASK)) | PSR_MODE_EL1h | PSR_PAN_BIT;
			}

			if (flags & _TIF_NOTIFY_RESUME)
				copied_resume_user_mode_work(regs);

			if (flags & _TIF_FOREIGN_FPSTATE)
				IMPORTED(fpsimd_restore_current_state)();

			continue;
		}

		PV_lz_assign_vmid_lock(lzcpu->proc);

		/*
		* This must be shared to run KVM simultaneously.
		*/
		regs->pstate = (regs->pstate & (~PSR_MODE_MASK) & (~PSR_UAO_BIT)) | PSR_MODE_EL1h;/* | PSR_UAO_BIT;*/
		lzcpu_load(lzcpu, regs->sp, &pvp);

		rc = lzcpu_enter_exit(lzcpu, regs, pvp);

		local_irq_enable();
		put_cpu();

		if (rc == ARM_EXCEPTION_IL) {
			printk(KERN_ERR "lightzone: The exit code is illegal hypervisor\n");
			break;
		}

		/* Preempt-enable */
		if (lz_handle_exit(lzcpu, rc))
			break;
	}

	return 0;	/* Once enter, no return. */
}

void __noreturn lz_vm_exit_panic_c(void)	/* In non-preemption. */
{
	lzcpu_t *lzcpu = this_cpu_read(scheduled_lzcpu);

	this_cpu_write(scheduled_lzcpu, NULL);

	lz_deactivate_traps(lzcpu);
	put_cpu();

	panic("lightzone: Panic on unexpected guest exception.\n");

	unreachable();
}

lzcpu_t *get_current_lzcpu(void)
{
	lzcpu_t *lzcpu;
	preempt_disable();
	lzcpu = this_cpu_read(scheduled_lzcpu);
	preempt_enable();
	return lzcpu;
}
