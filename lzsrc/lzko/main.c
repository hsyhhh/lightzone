/**
 * main.c - the entry to read-write the LightZone code
 *
 * LightZone let user processes to run in EL1 securely
 * for in-process isolation with PAN and changing TTBR0.
 * LightZone-fast/scalable/nested are supported. This
 * design can be ported to RISC-V and current AMD, too.
 * Since Intel has VMFUNC and MPK, while future AMD and
 * old ARM32 processors have MPK and Memory Domain for
 * efficient intra-process isolation, it is deprecated
 * to use LightZone on these machines by the authors.
 *
 * Authors:
 *   Ziqi Yuan   <yuanzqss@zju.edu.cn>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/version.h>
#include <uapi/asm-generic/siginfo.h>
#include <uapi/asm/ucontext.h>
#include <asm/syscall.h>

#include "lightzone.h"
#include "lzarm.h"
#include "lzcpu.h"
#include "paravirt.h"
#include "lowvisor.h"
#include "lzsym.h"

syscall_fn_t lz_syscall_tbl[__NR_syscalls] __cacheline_aligned;
extern struct rw_semaphore big_lz_lock;

static long lz_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	lzconf_t lzconf;
	lzmprot_t lzmprot;
	lzglz_t lzglz;
	long rc;
	int zoneid;
	lzcpu_t *current_lzcpu = get_current_lzcpu();

	switch (ioctl) {
		case LZ_ENTRY:
			rc = copy_from_user(&lzconf, (int __user *)arg,
					sizeof(lzconf_t));
			if (rc)
				return -EIO;
			return lz_entry(&lzconf, LZ_ENTRY_FROM_USER, NULL);	/* No return or re-entry */

		case LZ_ALLOC:
			if (!current_lzcpu)
				return -EINVAL;
			zoneid = lz_alloc(current_lzcpu->proc);
			if (zoneid == NR_LZID)
				return rc;
			rc = copy_to_user((void __user *)arg, &zoneid,
					sizeof(int));
			if (rc)
				return -EIO;
			break;

		case LZ_FREE:
			if (!current_lzcpu)
				return -EINVAL;
			rc = copy_from_user(&zoneid, (int __user *)arg,
					sizeof(int));
			if (rc)
				return -EIO;
			lz_free(zoneid, current_lzcpu);
			break;

		case LZ_MPROTECT:
			if (!current_lzcpu)
				return -EINVAL;
			rc = copy_from_user(&lzmprot, (int __user *)arg,
					sizeof(lzmprot_t));
			if (rc)
				return -EIO;
			lzmprot.rc = lz_mprotect(lzmprot.addr, lzmprot.len,
							lzmprot.zoneid, lzmprot.rc, current_lzcpu->proc);
			rc = copy_to_user((void __user *)arg, &lzmprot,
					sizeof(lzmprot_t));
			if (rc)
				return -EIO;
			break;

		case LZ_SET_GLZ:
			if (!current_lzcpu)
				return -EINVAL;
			rc = copy_from_user(&lzglz, (int __user *)arg,
					sizeof(lzglz_t));
			if (rc)
				return -EIO;
			lzglz.rc = lz_set_glz(lzglz.gateid, lzglz.zoneid, current_lzcpu->proc);
			rc = copy_to_user((void __user *)arg, &lzglz,
					sizeof(lzglz_t));
			if (rc)
				return -EIO;
			break;

		default:
			return -EINVAL;
	}

	return 0;
}

static int lz_dev_release(struct inode *inode, struct file *file) { return 0; }

static const struct file_operations lz_chardev_ops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl	= lz_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= lz_dev_ioctl,
#endif
	.llseek			= noop_llseek,
	.release		= lz_dev_release,
};

static struct miscdevice lz_dev = {
	LIGHTZONE_MINOR,
	"lightzone",
	&lz_chardev_ops,
};

int lz_sys_exit(struct pt_regs *regs)
{
	if (regs->orig_x0)
		lzcpu_destroy((lzcpu_t *)regs->orig_x0);
	regs->orig_x0 = regs->regs[0];
	(*((syscall_fn_t *)IMPORTED(sys_call_table) + __NR_exit))(regs);
	return 0;
}

int lz_sys_exit_group(struct pt_regs *regs)
{
	if (regs->orig_x0)
		lzcpu_destroy((lzcpu_t *)regs->orig_x0);
	regs->orig_x0 = regs->regs[0];
	(*((syscall_fn_t *)IMPORTED(sys_call_table) + __NR_exit_group))(regs);
	return 0;
}

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};

int lz_sys_rt_sigreturn(struct pt_regs *regs)
{
	int rc, err;
	struct rt_sigframe __user *frame = (struct rt_sigframe __user *)regs->sp;
	lzcpu_t *lzcpu = (lzcpu_t *)regs->orig_x0;
	bool pan = true;

	regs->orig_x0 = regs->regs[0];

	if (access_ok(frame, sizeof (*frame))) {
		__get_user_error(regs->pstate, &frame->uc.uc_mcontext.pstate, err);
		if (!err) {
			int zoneid = regs->pstate >> SYS_SPSR_RES0_USED_SHIFT;
			unsigned long __user *tab = (unsigned long *)(lzcpu->proc->ttbr0_tab_start +
					sizeof(unsigned long) * zoneid);
			lzcpu->ttbr0 = lzcpu->proc->default_ttbr0;
			pan = (regs->pstate & PSR_PAN_BIT);
			
			if (zoneid && get_user(lzcpu->ttbr0, tab)) {
				lzcpu->ttbr0 = lzcpu->proc->default_ttbr0;
				pan = true;
			}	
		}
	}
	rc = (*((syscall_fn_t *)IMPORTED(sys_call_table) + __NR_rt_sigreturn))(regs);
	if (pan)
		regs->pstate |= PSR_PAN_BIT;
	return rc;
}

int lz_put_new_thread_in(void *arg)
{
	struct pt_regs *child_regs = current_pt_regs();
	lz_clone_args_t *aux_args = (lz_clone_args_t *)arg;
	unsigned long stack_start = aux_args->stack;
	unsigned long clone_flags = aux_args->flags;
	lzconf_t lzconf = aux_args->conf;
	lzconf_el1_sys_t lzconf_el1_sys = aux_args->conf_el1_sys;

	*child_regs = aux_args->parent_regs;
	child_regs->regs[0] = 0;

	*task_user_tls(current) = aux_args->tpidr;
	write_sysreg(aux_args->tpidr, tpidr_el0);

	if (stack_start) {
		if (is_compat_thread(task_thread_info(current)))
			child_regs->compat_sp = stack_start;
		else
			child_regs->sp = stack_start;	/* Set later in lz_entry. */
	}

	/*
	 * If a TLS pointer was passed to clone, use it for the new
	 * thread.  We also reset TPIDR2 if it's in use.
	 */
	if (clone_flags & CLONE_SETTLS) {
		current->thread.uw.tp_value = aux_args->tls;
		write_sysreg(aux_args->tls, tpidr_el0);
	}

	kfree(aux_args);

	/*************************************************
	 *********** New thread into LightZone. **********
	 *************************************************/
	lz_entry(&lzconf, LZ_ENTRY_FROM_LZ, &lzconf_el1_sys);
	panic("lightzone: Panic on return of the cloned lz thread.\n");
	return 0;
}

int lz_sys_clone(struct pt_regs *regs)
{
	u64 old_pstate, rc;
	lzcpu_t *lzcpu = (lzcpu_t *)regs->orig_x0;
#ifdef CONFIG_CLONE_BACKWARDS
	unsigned long clone_flags = regs->regs[0];
	unsigned long newsp = regs->regs[1];
	int __user *parent_tidptr = (int *)regs->regs[2];
	int __user *child_tidptr = (int *)regs->regs[4];
	unsigned long tls = regs->regs[3];
#elif defined(CONFIG_CLONE_BACKWARDS2)
	unsigned long clone_flags = regs->regs[1];
	unsigned long newsp = regs->regs[0];
	int __user *parent_tidptr = (int *)regs->regs[2];
	int __user *child_tidptr = (int *)regs->regs[3];
	unsigned long tls = regs->regs[4];
#elif defined(CONFIG_CLONE_BACKWARDS3)
	unsigned long clone_flags = regs->regs[0];
	unsigned long newsp = regs->regs[1];
	int __user *parent_tidptr = (int *)regs->regs[3];
	int __user *child_tidptr = (int *)regs->regs[4];
	unsigned long tls = regs->regs[5];
#else
	unsigned long clone_flags = regs->regs[0];
	unsigned long newsp = regs->regs[1];
	int __user *parent_tidptr = (int *)regs->regs[2];
	int __user *child_tidptr = (int *)regs->regs[3];
	unsigned long tls = regs->regs[4];
#endif
	bool clone_vm = clone_flags & CLONE_VM;
	lz_clone_args_t *aux_args = clone_vm ? kzalloc(sizeof(lz_clone_args_t), GFP_KERNEL) : NULL;

	struct kernel_clone_args args = {
		.flags		= (lower_32_bits(clone_flags) & ~CSIGNAL),
		.pidfd		= parent_tidptr,
		.child_tid	= child_tidptr,
		.parent_tid	= parent_tidptr,
		.exit_signal	= (lower_32_bits(clone_flags) & CSIGNAL),
		.tls		= tls,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)
		.stack		= clone_vm ? (unsigned long)lz_put_new_thread_in : newsp,
		.stack_size	= clone_vm ? (unsigned long)aux_args : 0,
		.lightzone_process	= clone_vm ? 1 : 0,
#else
		/* 
		 * int (*fn)(void *);
		 * void *fn_arg;
		 * If we set these values, kernel will not copy the pt_regs of the
		 * parent process, so LightZone must do this to treat the new thread
		 * as a user thread rather than kthread.
		 * 
		 * See the modified copy_thread in /arch/arm64/kernel/process.c
		 */
		.stack		= newsp,
		.fn			= clone_vm ? lz_put_new_thread_in : NULL,
		.fn_arg		= clone_vm ? aux_args : NULL,
#endif
	};

	if (clone_vm) {
		if (!aux_args)
			return -ENOMEM;
		aux_args->parent_regs = *regs;
		aux_args->parent_regs.orig_x0 = regs->regs[0];
		aux_args->parent_regs.syscallno = __NR_clone;
		aux_args->stack = newsp;
		aux_args->flags = (lower_32_bits(clone_flags) & ~CSIGNAL);
		aux_args->tls   = tls;
		aux_args->tpidr = read_sysreg(tpidr_el0);
		
		/* Configure some EL1 states. */
		aux_args->conf.user_vbar = lzcpu->proc->vbar;
		aux_args->conf.ttbr0_tab_start = lzcpu->proc->ttbr0_tab_start;
		aux_args->conf.ttbr0_tab_end = lzcpu->proc->ttbr0_tab_end;
		aux_args->conf.call_gate_start = lzcpu->proc->call_gate_start;
		aux_args->conf.call_gate_end = lzcpu->proc->call_gate_end;
		aux_args->conf.per_gate_start = lzcpu->proc->per_gate_start;
		aux_args->conf.per_gate_end = lzcpu->proc->per_gate_end;
		aux_args->conf.scalable = (lzcpu->proc->hcr & HCR_VM);
		aux_args->conf_el1_sys.elr_el1 = lzcpu->elr_el1;
		aux_args->conf_el1_sys.spsr_el1 = lzcpu->spsr_el1;
	}

	/* The new thread ret_from_fork instead of return to this site. */
	regs->orig_x0 = regs->regs[0];
	if (!clone_vm) {
		old_pstate = regs->pstate;
		regs->pstate = (regs->pstate & (~(PSR_MODE_MASK | PSR_PAN_BIT | PSR_UAO_BIT))) | PSR_MODE_EL0t;
	}
	rc = IMPORTED(kernel_clone)(&args);
	if (!clone_vm)
		regs->pstate = old_pstate;
	return rc;
}

static void activate_cycle(void *info)
{
	unsigned long start_time, end_time;
	
	asm volatile("msr pmcr_el0, %0\n\t"
				 "msr pmcntenset_el0, %1\n\t"
				 "msr pmuserenr_el0, %2\n\t"
				 "msr pmccfiltr_el0, %3\n\t"
				 "nop\n" ::
				 "r" (ARMV8_PMU_PMCR_LC | ARMV8_PMU_PMCR_E),
				 "r" (1UL << 31), "r" (0xf), "r" (1UL << 27) : "memory");

	asm volatile("isb\n mrs %0, pmccntr_el0\n"
				 "isb\n"
				: "=r" (start_time));
	asm volatile("isb\n mrs %0, pmccntr_el0\n"
				 "isb\n"
				: "=r" (end_time));
}

void lzhcr_restore(void)
{	
	if (!(PV_read_sysreg_ho(hcr_el2) & HCR_TGE)) {
		PV_write_sysreg_ho(LZ_HCR_VAL | HCR_TGE, hcr_el2);
		isb();
	}
}

static int __init lz_init(void)
{
	int rc;

	printk(KERN_INFO "lightzone: Module installed\n");

	if ((rc = lz_arch_init_check())) {
		printk(KERN_ERR "lightzone: Failed to set up hardware support\n");
		return rc;
	}

	init_rwsem(&big_lz_lock);

	memcpy((void *)lz_syscall_tbl, (void *)(IMPORTED(sys_call_table)),
		   sizeof(syscall_fn_t) * __NR_syscalls);
	lz_syscall_tbl[__NR_exit] = (void *) &lz_sys_exit;
	lz_syscall_tbl[__NR_exit_group] = (void *) &lz_sys_exit_group;
	lz_syscall_tbl[__NR_clone] = (void *) &lz_sys_clone;
	lz_syscall_tbl[__NR_rt_sigreturn] = (void *) &lz_sys_rt_sigreturn;

	rc = misc_register(&lz_dev);
	if (rc) {
		printk(KERN_ERR "lightzone: Misc device register failed\n");
		return rc;
	}

	rc = PV_lz_register_lowvisor();
	if (rc)
		return rc;

	*IMPORTED(lzcpu_destroy_wrapper) = (void (*)(void *))lzcpu_destroy;
#ifdef TGE_OPT_EL2
	*IMPORTED(lzhcr_check_update) = lzhcr_restore;
#endif
	
	on_each_cpu(activate_cycle, NULL, 1);
	return PV_lz_share_all_vcpu_pages();
}

static void __exit lz_exit(void)
{
	misc_deregister(&lz_dev);
	PV_lz_unregister_lowvisor();
	*IMPORTED(lzcpu_destroy_wrapper) = NULL;
#ifdef TGE_OPT_EL2
	*IMPORTED(lzhcr_check_update) = NULL;
#endif
}

module_init(lz_init);
module_exit(lz_exit);

MODULE_AUTHOR("Ziqi Yuan <yuanzqss@zju.edu.cn>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LightZone-AArch64 Driver");
