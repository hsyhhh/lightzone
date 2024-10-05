#include <linux/ptrace.h>
#include <linux/freezer.h>
#include <linux/preempt.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/sched/cputime.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_arm.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <asm/vdso.h>
#include <uapi/asm/ucontext.h>
#include <uapi/asm-generic/signal.h>

#include <trace/events/signal.h>

#include "lightzone.h"
#include "lzcpu.h"
#include "copied.h"

void copied_resume_user_mode_work(struct pt_regs *regs)
{
    clear_thread_flag(TIF_NOTIFY_RESUME);
	smp_mb__after_atomic();
	if (unlikely(current->task_works))
		IMPORTED(task_work_run)();
#ifdef CONFIG_KEYS_REQUEST_CACHE
	if (unlikely(current->cached_requested_key)) {
		key_put(current->cached_requested_key);
		current->cached_requested_key = NULL;
	}
#endif
	IMPORTED(mem_cgroup_handle_over_high)();
	IMPORTED(blkcg_maybe_throttle_current)();
	if (current->rseq)
		IMPORTED(__rseq_handle_notify_resume)(NULL, regs);
}

static __always_inline void __load_stage2(lzproc_t *lzproc)
{
	write_sysreg(lzproc->vtcr, vtcr_el2);
	write_sysreg(lzproc->vttbr, vttbr_el2);

	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL1/EL0 translation regime used by
	 * the guest.
	 */
	asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));
}

void copied___tlb_switch_to_host(struct tlb_inv_context *cxt, u64 hcr, u64 vttbr)
{
	write_sysreg(vttbr, vttbr_el2);
	write_sysreg(hcr, hcr_el2);
	isb();

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/* Restore the registers to what they were */
		write_sysreg_el1(cxt->tcr, SYS_TCR);
		write_sysreg_el1(cxt->sctlr, SYS_SCTLR);
	}

	local_irq_restore(cxt->flags);
}

void copied___tlb_switch_to_guest(struct tlb_inv_context *cxt, lzproc_t *lzproc)
{
	u64 val;

	local_irq_save(cxt->flags);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/*
		 * For CPUs that are affected by ARM errata 1165522 or 1530923,
		 * we cannot trust stage-1 to be in a correct state at that
		 * point. Since we do not want to force a full load of the
		 * vcpu state, we prevent the EL1 page-table walker to
		 * allocate new TLBs. This is done by setting the EPD bits
		 * in the TCR_EL1 register. We also need to prevent it to
		 * allocate IPA->PA walks, so we enable the S1 MMU...
		 */
		val = cxt->tcr = read_sysreg_el1(SYS_TCR);
		val |= TCR_EPD1_MASK | TCR_EPD0_MASK;
		write_sysreg_el1(val, SYS_TCR);
		val = cxt->sctlr = read_sysreg_el1(SYS_SCTLR);
		val |= SCTLR_ELx_M;
		write_sysreg_el1(val, SYS_SCTLR);
	}

	/*
	 * With VHE enabled, we have HCR_EL2.{E2H,TGE} = {1,1}, and
	 * most TLB operations target EL2/EL0. In order to affect the
	 * guest TLBs (EL1/EL0), we need to change one of these two
	 * bits. Changing E2H is impossible (goodbye TTBR1_EL2), so
	 * let's flip TGE before executing the TLB operation.
	 *
	 * ARM erratum 1165522 requires some special handling (again),
	 * as we need to make sure both stages of translation are in
	 * place before clearing TGE. __load_stage2() already
	 * has an ISB in order to deal with this.
	 */
	__load_stage2(lzproc);
	val = read_sysreg(hcr_el2);
	val &= ~HCR_TGE;
	write_sysreg(val, hcr_el2);
	isb();
}
