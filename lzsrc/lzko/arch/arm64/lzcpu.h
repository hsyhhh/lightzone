#ifndef __ARM64_LZCPU_H__
#define __ARM64_LZCPU_H__

#include "lightzone.h"
#include <linux/list.h>
#include <linux/version.h>
#include "lzsym.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,0,0)

#define NEED_NEW_VMID_GENERATION()		IMPORTED(need_new_vmid_gen)(&lzcpu->proc->vmid)

static inline bool lz_assign_vmid(lzproc_t *lzproc, bool irq_disabled)
{
	u64 vmid_field;
	int vmid_bit = (lzproc->vtcr & VTCR_EL2_VS_16BIT) ? 16 : 8;

	if (IMPORTED(update_vmid)(&lzproc->vmid, irq_disabled))
		return true;
	vmid_field = (u64)(lzproc->vmid.vmid) << VTTBR_VMID_SHIFT;
	vmid_field &= VTTBR_VMID_MASK(vmid_bit);
	lzproc->vttbr = phys_to_ttbr(lzproc->s2_pgd_phys) | vmid_field;
	return false;
}

static inline void lz_assign_vmid_lock(lzproc_t *lzproc)
{
	return;
}
#else

#define NEED_NEW_VMID_GENERATION()		(0)

static inline bool lz_assign_vmid(lzproc_t *lzproc, bool irq_disabled)
{
	return false;
}

static inline void lz_assign_vmid_lock(lzproc_t *lzproc)
{
	u64 vmid_field;
	int vmid_bit = (lzproc->vtcr & VTCR_EL2_VS_16BIT) ? 16 : 8;

	IMPORTED(kvm_arm_vmid_update)(&lzproc->vmid);
	vmid_field = atomic64_read(&lzproc->vmid.id) << VTTBR_VMID_SHIFT;
	vmid_field &= VTTBR_VMID_MASK(vmid_bit);
	lzproc->vttbr = phys_to_ttbr(lzproc->s2_pgd_phys) | vmid_field;
}
#endif

lzcpu_t *lzcpu_create(lzconf_t *lzconf, int from, lzconf_el1_sys_t *lzconf_el1_sys);
void lzcpu_destroy(lzcpu_t *lzcpu);
int lzcpu_run(lzcpu_t *lzcpu);
lzcpu_t *get_current_lzcpu(void);
int lz_gate_tab_init(lzproc_t *proc);

#endif