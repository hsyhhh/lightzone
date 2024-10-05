#ifndef __ARM64_LZPARAVIRT_H__
#define __ARM64_LZPARAVIRT_H__

#include "lightzone.h"

#ifdef RUN_ON_VHE_HOST

#define PVSYS_ESR									SYS_ESR
#define PVSYS_FAR									SYS_FAR
#define PVSYS_ELR									SYS_ELR
#define PVSYS_SPSR									SYS_SPSR
#define PVSYS_TTBR0									SYS_TTBR0
#define PVSYS_TCR									SYS_TCR
#define PVSYS_CPACR									SYS_CPACR
#define PVSYS_CNTKCTL								SYS_CNTKCTL
#define PVSYS_TTBR1									SYS_TTBR1
#define PVSYS_VBAR									SYS_VBAR
#define PV_read_sysreg_el1(r, pvp)					read_sysreg_el1(r)
#define PV_read_sysreg_el2(r, pvp)					read_sysreg_el2(r)
#define PV_read_sysreg(r, pvp)						read_sysreg(r)
#define PV_write_sysreg_el1(v, r, pvp)				write_sysreg_el1(v, r)
#define PV_write_sysreg_el1_ho(v, r)				write_sysreg_el1(v, r)
#define PV_write_sysreg_el2(v, r, pvp)				write_sysreg_el2(v, r)
#define PV_write_sysreg(v, r, pvp)					write_sysreg(v, r)
#define PV_write_sysreg_ho(v, r)					write_sysreg(v, r)
#define PV_read_sysreg_ho(r)						read_sysreg(r)
#define PV_write_sysreg_for_kernel(v, r, pvp)		write_sysreg(v, r)

#define PV_trig_stage2(hva, hpfar, esr)				(0)
#define PV_isb_ho()									isb()
#define get_pv_page(cpu)							(NULL)
#define PV_lz_assign_vmid(proc, irqd)				lz_assign_vmid(proc, irqd)
#define PV_lz_assign_vmid_lock(proc)				lz_assign_vmid_lock(proc)
#define PV_lz_setup_stage2(proc)					lz_setup_stage2(proc)
#define PV_lz_init_stage2_mmu_locked(proc)			lz_init_stage2_mmu_locked(proc)
#define PV_lz_register_notifier(proc)				lz_register_notifier(proc)
#define PV_write_lzproc_go(proc, pvp)				do {} while (0)
#define PV_NEED_NEW_VMID_GENERATION()				NEED_NEW_VMID_GENERATION()
#define PV_lz_register_lowvisor()					lz_register_lowvisor()
#define PV_lz_unregister_lowvisor()					lz_unregister_lowvisor()
#define PV_lz_share_all_vcpu_pages()				(0)
#define PV_npt_inv_ipa(p, s2pgd, ipa, pvp, l)		npt_inv_ipa(p, s2pgd, ipa)
#define get_pv_page_aq()							(NULL)
#define put_pv_page_rl()							do {} while (0)
#define PV_npt_inv_empty(pvp)						(0)
#define PV_npt_inv_action(p, pvp)					do {} while (0)
#define PV_init_lzcpu_pt_regs(regs, lzcpu)			(0)
#define PV_lz_vm_entry(regs, lzcpu)					lz_vm_entry(regs)
#define PV_zap_lzcpu_pt_regs(regs_pa)				do {} while (0)
#define PV_handle_nested_page_fault(p, s2pgt, ipa, hpa, level, flags)\
													handle_nested_page_fault(p, s2pgt, ipa, hpa, level, flags)
#define PV_destroy_nested_pgtable(p, s2pgd, ia, sl, free_s2pgd)\
													if ((p)->hcr & HCR_VM) destroy_nested_pgtable(p, s2pgd, ia, sl, free_s2pgd)
#define PV_convert_aligned_pa(pte_seqpa, hva, lev)		(pte_seqpa)

#define PV_lz_flush_tlb_by_vmid_s1(p, a)			lz_flush_tlb_by_vmid_s1(p, a)
#define PV_lz_flush_tlb_by_vmid(p, ipa, g)			lz_flush_tlb_by_vmid(p, ipa, g)
#define PV_flush_tlb_mm_ho(mm)						flush_tlb_mm(mm)

#else   /* RUN IN GUEST */

int lowvisor_call_setup_stage2(lzproc_t *lzproc);
int lowvisor_call_share_all_vcpu_pages(void);
int guest_lz_register_notifier(lzproc_t *lzproc);
int guest_npt_inv_ipa(lzproc_t *lzproc, pgd_t *s2_pgd_base, unsigned long ipa, int lev, lzpage_t *pvp);
int lowvisor_call_npt_inv_action(lzproc_t *lzproc, lzpage_t *pvp);
int lowvisor_call_handle_nested_page_fault(lzproc_t *lzproc, unsigned long ipa,
			unsigned long hpa, unsigned long flags);
int lowvisor_call_destroy_nested_pgtable(lzproc_t *lzproc);
int lowvisor_call_setup_pt_regs(struct pt_regs *regs, lzcpu_t *lzcpu);
int lowvisor_call_zap_pt_regs(unsigned long regs_pa);
int lowvisor_call_eager_fault_stage2(unsigned long hva, unsigned long hpfar, unsigned long esr);
unsigned long guest_convert_seqpa(unsigned long aligned_seqpa, unsigned long hva, int lev);

inline static u64 lowvisor_call_vm_entry(unsigned long pt_regs_pa)
{
	u64 exit_code;

	asm volatile (
		"mov x0, %1\n\t"
		"hvc #1\n\t"
		"mov %0, x0"
		: "=r" (exit_code) : "r" (pt_regs_pa): "x0", "memory"
	);

	return exit_code;
}

#define PV_JOIN(a, b)								a ## b
#define PVSYS_ESR									esr_
#define PVSYS_FAR									far_
#define PVSYS_ELR									elr_
#define PVSYS_SPSR									spsr_
#define PVSYS_TTBR0									ttbr0_
#define PVSYS_TCR									tcr_
#define PVSYS_CPACR									cpacr_
#define PVSYS_CNTKCTL								cntkctl_
#define PVSYS_TTBR1									ttbr1_
#define PVSYS_VBAR									vbar_
#define PV_read_sysreg_el1(r, pvp)					((pvp)->PV_JOIN(r, el1))
#define PV_read_sysreg_el2(r, pvp)					((pvp)->PV_JOIN(r, el2))
#define PV_read_sysreg(r, pvp)						((pvp)->r)
#define PV_write_sysreg_el1(v, r, pvp)				((pvp)->PV_JOIN(r, el1) = (v))
#define PV_write_sysreg_el1_ho(v, r)				do {} while (0)
#define PV_write_sysreg_el2(v, r, pvp)				((pvp)->PV_JOIN(r, el2) = (v))
#define PV_write_sysreg(v, r, pvp)					((pvp)->r = (v))
#define PV_write_sysreg_ho(v, r)					do {} while (0)
#define PV_read_sysreg_ho(r)						(0)
#define PV_write_sysreg_for_kernel(v, r, pvp)		do {} while (0)

#define PV_trig_stage2(hva, hpfar, esr)				lowvisor_call_eager_fault_stage2(hva, hpfar, esr)
#define PV_isb_ho()									do {} while (0)
#define get_pv_page(cpu)							(all_per_vcpu_pages ? (lzpage_t *)(&all_per_vcpu_pages[(cpu) * PAGE_SIZE]) : NULL)
#define PV_lz_assign_vmid(proc, irqd)				do {} while (0)
#define PV_lz_assign_vmid_lock(proc)				do {} while (0)
#define PV_lz_setup_stage2(proc)					lowvisor_call_setup_stage2(proc)
#define PV_lz_init_stage2_mmu_locked(proc)			(0)
#define PV_lz_register_notifier(proc)				guest_lz_register_notifier(proc)
#define PV_write_lzproc_go(proc, pvp)				((pvp)->guest_proc_va = (unsigned long)(proc))
#define PV_NEED_NEW_VMID_GENERATION()				(0)
#define PV_lz_register_lowvisor()					(0)
#define PV_lz_unregister_lowvisor()					do {} while (0)
#define PV_lz_share_all_vcpu_pages()				lowvisor_call_share_all_vcpu_pages()
#define PV_npt_inv_ipa(p, s2pgd, ipa, pvp, l)		guest_npt_inv_ipa(p, s2pgd, ipa, l, pvp)
#define get_pv_page_aq()							(all_per_vcpu_pages ? (lzpage_t *)(&all_per_vcpu_pages[get_cpu() * PAGE_SIZE]) : NULL)
#define put_pv_page_rl()							put_cpu()
#define PV_npt_inv_empty(pvp)						((pvp)->vma_idx == 0)
#define PV_npt_inv_action(p, pvp)					if (pvp->vma_idx) lowvisor_call_npt_inv_action(p, pvp)
#define PV_init_lzcpu_pt_regs(regs, lzcpu)			lowvisor_call_setup_pt_regs(regs, lzcpu)
#define PV_lz_vm_entry(regs, lzcpu)					lowvisor_call_vm_entry((lzcpu)->pt_regs_pa)
#define PV_zap_lzcpu_pt_regs(regs_pa)				lowvisor_call_zap_pt_regs(regs_pa)
#define PV_handle_nested_page_fault(p, s2pgt, ipa, hpa, level, flags)\
													lowvisor_call_handle_nested_page_fault(p, ipa, hpa, flags)
#define PV_destroy_nested_pgtable(p, s2pgd, ia, sl, free_s2pgd)\
													lowvisor_call_destroy_nested_pgtable(p)
#define PV_convert_aligned_pa(pte_seqpa, hva, lev)		guest_convert_seqpa((pte_seqpa), (hva), (lev))

#define PV_lz_flush_tlb_by_vmid_s1(p, a)			do {\
														asm volatile (\
															"mov x0, %0\n\t"\
															"hvc #2"\
															:: "r" (p) : "x0", "memory"\
														);\
													} while(0)
#define PV_lz_flush_tlb_by_vmid(p, ipa, g)			do {\
														if (!((p)->hcr & HCR_VM))\
															asm volatile (\
																"mov x0, %0\n\t"\
																"hvc #2"\
																:: "r" (p) : "x0", "memory"\
															);\
													} while(0)
#define PV_flush_tlb_mm_ho(mm)						do {} while (0)

#endif

#endif