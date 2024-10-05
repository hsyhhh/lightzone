/**
 * arch/arm64/arm.c - the code about EL2 for AArch64 CPU.
 * LightZone must be loaded after kvm is loaded and
 * initialized and can co-work with kvm.
 *
 * Authors:
 *   Ziqi Yuan   <yuanzqss@zju.edu.cn>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <asm/virt.h>
#include <asm/kvm_hyp.h>

#include "lzarm.h"
#include "npt.h"
#include "lzcpu.h"
#include "copied.h"

u64 host_init_hcr_el2;
u64 host_init_cptr_el2;
u64 host_init_cnthctl_el2;
u64 host_init_mdcr_el2;
int max_available_asids;

/**
 * Initialize EL2 and memory mappings on all CPUs.
 */
int lz_arch_init_check(void)
{
#ifdef RUN_ON_VHE_HOST
	
	if (!(((u32 *)(IMPORTED(__boot_cpu_mode)))[0] == BOOT_CPU_MODE_EL2 &&
		((u32 *)(IMPORTED(__boot_cpu_mode)))[1] == BOOT_CPU_MODE_EL2)) {
		printk(KERN_ERR "lightzone: HYP mode not available\n");
		return -ENODEV;
	}

	if (lz_set_ipa_limit())
		return -EINVAL;

	/**
	 * LightZone depends on kvm in VMID management for simultaneous execution
	 * We also depend on the kvm sub-system initialization for simplicity
	 */
	if (!is_kernel_in_hyp_mode() || !has_vhe()) {
		printk(KERN_ERR "lightzone: Failed to support nVHE configuration temporarily.\n");
		return -ENODEV;
	}

	printk(KERN_INFO "lightzone: VHE mode initialized successfully\n");

	host_init_hcr_el2 = read_sysreg(hcr_el2);
	host_init_cptr_el2 = read_sysreg(cpacr_el1);
	host_init_cnthctl_el2 = read_sysreg(cnthctl_el2);
	host_init_mdcr_el2 = read_sysreg(mdcr_el2);
#else
	printk(KERN_INFO "lightzone: Guest mode initialized successfully\n");
#endif
	max_available_asids = 256;

	return 0;
}

int lz_entry(lzconf_t *lzconf, int from, lzconf_el1_sys_t *lzconf_el1_sys)
{
	extern int lz_sys_exit_group(struct pt_regs *regs);
	struct pt_regs *regs;
	lzcpu_t *lzcpu = lzcpu_create(lzconf, from, lzconf_el1_sys);

	if (lzcpu)
		lzcpu_run(lzcpu);

	regs = current_pt_regs();
	regs->regs[0]   = 0;
	regs->regs[8]   = __NR_exit_group;
	regs->orig_x0   = (unsigned long)lzcpu;
	regs->syscallno = __NR_exit_group;
	lz_sys_exit_group(regs);

	return 0;
}

/* Refer to kvm_flush_remote_tlbs(kvm). */
void lz_flush_tlb_by_vmid(lzproc_t *lzproc, unsigned long ipa, bool in_guest)
{
	struct tlb_inv_context cxt;
	u64 hcr, vttbr;

	dsb(ishst);

	if (in_guest) {	/* IRQ disabled */
		hcr = read_sysreg(hcr_el2);
		vttbr = read_sysreg(vttbr_el2);
	} else {
		hcr = HCR_RW | HCR_TGE | HCR_E2H;
		vttbr = 0;
	}

	/* Switch to requested VMID */
	copied___tlb_switch_to_guest(&cxt, lzproc);

	if (ipa) {
		__tlbi_level(ipas2e1is, ipa >> 12, 0);
		dsb(ish);
		__tlbi(vmalle1is);
	} else
		__tlbi(vmalls12e1is);

	dsb(ish);
	isb();

	copied___tlb_switch_to_host(&cxt, hcr, vttbr);
	isb();
}

void lz_flush_tlb_by_vmid_s1(lzproc_t *lzproc, unsigned long gva)
{
	struct tlb_inv_context cxt;
	dsb(ishst);

	/* Switch to requested VMID */
	copied___tlb_switch_to_guest(&cxt, lzproc);

	if (gva)
		__tlbi(vale1is, __TLBI_VADDR(gva, 0));
	else
		__tlbi(vmalle1is);
	dsb(ish);
	isb();

	copied___tlb_switch_to_host(&cxt, HCR_RW | HCR_TGE | HCR_E2H, 0);
	isb();
}
