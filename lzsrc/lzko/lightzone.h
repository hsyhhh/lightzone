#ifndef __LIGHTZONE_H__
#define __LIGHTZONE_H__

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/preempt.h>
#include <asm/kvm_host.h>
#include <uapi/asm/ptrace.h>

#ifndef HCR_TAC
#define HCR_TAC		HCR_TACR
#endif

#define LIGHTZONE_MINOR		182

#define NR_LZID		128
#define NOPROT_LZID	(-1)

#define LZ_ENTRY_FROM_LZ	0
#define LZ_ENTRY_FROM_USER	1

#define ICH_HCR_TC						(1 << 10)
#define ICH_HCR_TALL0					(1 << 11)
#define ICH_HCR_TALL1					(1 << 12)
#define ICH_HCR_TDIR					(1 << 14)
#define CPACR_EL1_FPEN_EL1EN			(BIT(20)) /* enable EL1 access */
#define CPACR_EL1_FPEN_EL0EN			(BIT(21)) /* enable EL0 access, if EL1EN set */

#define LZ_USER_TTBR1_MASK				0xffff000000000000UL
#define SYS_SPSR_RES0_USED_SHIFT		48
#define TTBR0_TAB_START_EL1				0xffff800000000000UL	/* Never mapped by EL0 */
#define PER_GATE_ZONE_RET_START_EL1		0xffffa00000000000UL	/* Never mapped by EL0 */
#define CALL_GATE_START_EL1				0xffff800000010000UL	/* Never mapped by EL0 */
#define NR_LOWVISOR_CALL_DISCONT_VMA	128
#define LZ_CPTR_SET_VAL					(CPTR_EL2_TCPAC | CPACR_EL1_TTA | CPTR_EL2_TAM)
#define LZ_HCR_VAL	(HCR_SWIO | HCR_FB | HCR_BSU_IS |\
				   HCR_TWI | HCR_TWE | HCR_TSC | HCR_TID1 |\
				   HCR_FMO | HCR_TID3 | HCR_TEA| HCR_TIDCP |\
				   HCR_TAC | HCR_TSW | HCR_IMO | HCR_AMO |\
				   HCR_TDZ | HCR_RW | HCR_E2H | HCR_TLOR |\
				   HCR_TERR| HCR_TPU | HCR_TPC)
#define LZ_ICH_HCR_SET_VAL				(ICH_HCR_TDIR | ICH_HCR_TALL0 |\
										 ICH_HCR_TALL1 | ICH_HCR_TC)
#ifdef LIGHTZONE_RELEASE
#define LZ_MDCR_SET_VAL					(MDCR_EL2_TPM | MDCR_EL2_TPMS |\
										 MDCR_EL2_TTRF | MDCR_EL2_TPMCR |\
										 MDCR_EL2_TDRA | MDCR_EL2_TDOSA |\
										 MDCR_EL2_TDA)
#else	/* For profiling */
#define LZ_MDCR_SET_VAL					(MDCR_EL2_TDRA | MDCR_EL2_TDOSA |\
										 MDCR_EL2_TTRF | MDCR_EL2_TDA)
#endif
#define LZ_CNTHCTL_UNSET_VAL			((CNTHCTL_EL1PCEN << 10) | (CNTHCTL_EL1PCTEN << 10))

#define LZ_P4D_TYPE_TABLE				(_AT(p4dval_t, 3) << 0)
#define LZ_PF_GATE						(1UL << 0)
#define LZ_PF_WRITE						(1UL << 1)
#define LZ_PF_INST						(1UL << 2)
#define LZ_PF_STAGE1					(1UL << 3)
#define LZ_PF_PAN						(1UL << 4)
#define LZ_PF_IGNSCAN					(1UL << 5)
#define LZ_PF_PFNMAP					(1UL << 6)
#define LZ_PF_IO						(1UL << 7)
#define LZ_PF_LEV_SHIFT					(8)
#define LZ_PF_LEV_MASK					(3UL << 8)
#define LZ_PF_INIT						(LZ_PF_INST | LZ_PF_STAGE1)
#define LZ_PF_IN_GUEST					(1UL << 10)

typedef struct {
	phys_addr_t	s1_pgd_phys;
	phys_addr_t s1_pgd_seq;
	u64 s1_asid;
	struct list_head list_s1_mmu;
} lzpgt_t;

typedef struct {
	unsigned long user_vbar;
	unsigned long ttbr0_tab_start;
	unsigned long ttbr0_tab_end;
	unsigned long call_gate_start;
	unsigned long call_gate_end;
	unsigned long per_gate_start;
	unsigned long per_gate_end;
	bool scalable;
} lzconf_t;	/* LightZone Control Structure */

typedef struct {
	unsigned long addr;
	size_t len;
	int zoneid;
	int rc;
} lzmprot_t;

typedef struct {
	int zoneid;
	int gateid;
	int rc;
} lzglz_t;

typedef struct {
	struct rb_node node;
	unsigned long start;
	unsigned long end;
	int zoneid[4];
	int perm[4];	/* R, RW, RX, RWX permission overlays */
} lzrange_t;

typedef struct {
	unsigned long elr_el1;
	unsigned long spsr_el1;
} lzconf_el1_sys_t;

typedef struct {
	long zoneid;
	unsigned long retaddr;
} lz_per_gate_t;

/***************** Defend against rowhammer BEGIN ****************/
#define IPA_PTE_MASK					(0x0000001ff000ULL)
#define IPA_PMD_MASK					(0x00003ffff000ULL)
#define IPA_PUD_MASK					(0x007ffffff000ULL)
#define IPA_PGD_MASK					(0xfffffffff000ULL)

#define IPA_PTE_INC						(0x00001000UL)
#define IPA_PMD_INC						(0x00200000UL)
#define IPA_PUD_INC						(0x40000000UL)

typedef struct {
	unsigned long pte_aligned_cnt;
	unsigned long pmd_aligned_cnt;
	unsigned long pud_aligned_cnt;
	unsigned long *seqtable_base;
} ipa_counters_t;
/****************** Defend against rowhammer END *****************/

typedef struct lzproc_t {
	struct mm_struct *host_mm;	/* host mm_struct */
	struct list_head list_proc;
	struct list_head list_s1_mmu;
	unsigned long hcr;			/* always host controlled */
	atomic64_t nr_users;
	spinlock_t proc_lock;
	struct mmu_notifier mn;
	struct page **per_gate_pages;
	/* Per-proc arch-specific registers */
	unsigned long vbar;
	unsigned long ttbr1;
	unsigned long default_ttbr0;
	/* Per-proc zoneid RO-metadata pointer */
	unsigned long ropages;
	struct rb_root lzrange;
	union {
		struct {
			/* Communicate with LIBLZ */
			unsigned long ttbr0_tab_start;
			unsigned long ttbr0_tab_end;
			unsigned long call_gate_start;
			unsigned long call_gate_end;
			unsigned long per_gate_start;	/* s64 zoneid, u64 retaddr */
			unsigned long per_gate_end;
		};
		struct {
			/* For Lowvisor only */
			unsigned long guest_proc;
			struct kvm *kvm;
			spinlock_t lowvisor_lock;
		};
	};
	ipa_counters_t counters;
	/* Bitmap */
	unsigned long zone_bm[NR_LZID / __SIZEOF_LONG__ / 8];
	/* For scalable LightZone only */
	phys_addr_t	s2_pgd_phys;	/* always host controlled */
	u32 start_level;			/* always host controlled */
	u32 ia_bits;				/* always host controlled */
	struct kvm_vmid vmid;		/* always host controlled */
	unsigned long vtcr;			/* always host controlled */
	unsigned long vttbr;		/* always host controlled */
	atomic_t mn_gen;
	atomic_t vbar_unmapped;
	atomic_t mn_start_end_balance;
} lzproc_t;

typedef struct {
	unsigned long sp_el1;
	unsigned long far_el1;
	unsigned long esr_el1;
	unsigned long elr_el1;
	unsigned long spsr_el1;
	unsigned long ttbr0_el1;
	unsigned long ttbr1_el1;
	unsigned long cntkctl_el1;
	unsigned long cpacr_el1;
	unsigned long tcr_el1;
	unsigned long vbar_el1;
	unsigned long esr_el2;			/* Needed by S2PF */
	unsigned long elr_el2;
	unsigned long spsr_el2;
	unsigned long far_el2;			/* Needed by S2PF */
	unsigned long hpfar_el2;		/* Needed by S2PF */
	unsigned long guest_proc_va;	/* Needed by S2PF */
	unsigned long vma_idx;
	struct {
		unsigned long discont_begin;
		unsigned long discont_end;
	} unmap_areas[NR_LOWVISOR_CALL_DISCONT_VMA];
} lzpage_t;

typedef struct {
	struct mm_struct *host_mm;
	struct kvm_vcpu *vcpu;
	struct kvm *kvm;
	struct list_head list_ptr_lzpage;
	lzpage_t *pvp;
} ptr_lzpage_t;

typedef struct {
	unsigned long gpa;
	unsigned long hva;
	atomic64_t nr_users;
	struct kvm *kvm;
	struct list_head list_sregs;
} lzsregs_t;

typedef struct {
	lzproc_t *proc;
	/* Notifiers. */
	struct preempt_notifier pn;
	struct list_head list_cpu;
	/* Arch-specific contexts for LightZone process. */
	unsigned long ttbr0;
	unsigned long far;
	unsigned long hpfar;
	unsigned long esr;
	unsigned long esr_el1;
	unsigned long far_el1;
	unsigned long elr_el1;
	unsigned long spsr_el1;
	/* Scheduling-related. */
	int cpu;
	bool first_sched_in;
	/* For paravirt */
	unsigned long pt_regs_pa;
} lzcpu_t;

typedef struct {
	int (*pgd_ops)(pgd_t *pnpgd, unsigned long data);
	int (*pud_ops)(pud_t *pnpud, unsigned long data);
	int (*pmd_ops)(pmd_t *pnpmd, unsigned long data);
	unsigned long data;	/* can be an address */
} lz_walk_pt_ops_t;	/* Works for pt and npt. */

typedef void (*sys_call_ptr_t)(void);

typedef struct {
	struct pt_regs parent_regs;
	unsigned long stack;
	unsigned long flags;
	unsigned long tls;
	unsigned long tpidr;
	unsigned long tpidr2;
	lzconf_t conf;
	lzconf_el1_sys_t conf_el1_sys;
} lz_clone_args_t;

/***************** Don't change the layout BEGIN ****************/
typedef struct {
	unsigned long regs[31];
	unsigned long sp;
} lzctxt_host_t;
/****************** Don't change the layout END *****************/

DECLARE_PER_CPU(lzctxt_host_t, lz_host_ctxt);
DECLARE_PER_CPU(struct pt_regs *, lz_guest_ctxt);

#define MAX_LOWVISOR_NESTED_MMUS				64		/* Concurrent LightZone processes */
#define MAX_LOWVISOR_SHARED_REGS				4096	/* Concurrent LightZone threads */
#define LOWVISOR_CALL_VM_SWITCH_ISS				1
#define LOWVISOR_CALL_TLBI_ISS					2
#define LOWVISOR_CALL_UNMAP_TLBI_ISS			3
#define LOWVISOR_CALL_FAULT_ISS					4
#define LOWVISOR_CALL_SETUP_STAGE2				0xc001bab0UL
#define LOWVISOR_CALL_ZAP_STAGE2				0xc001bab1UL
#define LOWVISOR_CALL_SETUP_PT_REGS				0xc001bab2UL
#define LOWVISOR_CALL_ZAP_PT_REGS				0xc001bab3UL
#define LOWVISOR_CALL_SETUP_NESTED_MMUS			0xc001bab4UL
#define LOWVISOR_CALL_SETUP_SHARED_REGS			0xc001bab5UL
#define LOWVISOR_CALL_KVM_GUEST_ABORT			0xc001bab6UL
#define LOWVISOR_CALL_SHARE_VCPU_PAGE			0xc001bab7UL

/***************** LightZone Protection BEGIN *******************/
#define LZ_ENTRY		_IOR(LIGHTZONE_MINOR, 0x01, lzconf_t)
#define LZ_ALLOC		_IOR(LIGHTZONE_MINOR, 0x02, int)
#define LZ_FREE			_IOW(LIGHTZONE_MINOR, 0x03, int)
#define LZ_MPROTECT		_IOWR(LIGHTZONE_MINOR, 0x04, lzmprot_t)
#define LZ_SET_GLZ		_IOWR(LIGHTZONE_MINOR, 0x05, lzglz_t)

#define LZ_PROT_NOSAN	(1 << 0)
#define LZ_PROT_READ	(1 << 1)
#define LZ_PROT_WRITE	(1 << 2)
#define LZ_PROT_EXEC	(1 << 3)
#define LZ_PROT_UNPROT	(1 << 4)
#define LZ_PROT_DEF		(LZ_PROT_READ | LZ_PROT_WRITE | LZ_PROT_EXEC | LZ_PROT_UNPROT)

int lz_alloc(lzproc_t *proc);
void lz_free(int zoneid, lzcpu_t *lzcpu);
int lz_mprotect(unsigned long addr, size_t len, int zoneid, int prot, lzproc_t *proc);
int lz_set_glz(int gateid, int zoneid, lzproc_t *proc);
int lz_bind_call_site(lzproc_t *proc, int gateid, unsigned long retaddr);
/******************* LightZone Protection END *******************/

#endif
