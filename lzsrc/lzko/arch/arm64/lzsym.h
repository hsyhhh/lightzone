#ifndef __ARM64_LZSYM_H__
#define __ARM64_LZSYM_H__

extern void (*lzhcr_check_update)(void);
extern void do_signal(struct pt_regs *regs, void *lzcpu);
extern bool update_vmid(struct kvm_vmid *vmid, bool irq_disabled);
extern char vectors[];
extern const syscall_fn_t sys_call_table[];
extern u32 __boot_cpu_mode[2];
extern __noreturn void do_group_exit(int);
extern pid_t kernel_clone(struct kernel_clone_args *kargs);
extern void fpsimd_restore_current_state(void);
extern void mem_cgroup_handle_over_high(void);
extern void task_work_run(void);
extern void blkcg_maybe_throttle_current(void);
extern void __rseq_handle_notify_resume(struct ksignal *ksig, struct pt_regs *regs);
extern int expand_stack(struct vm_area_struct *vma, unsigned long address);
extern void (*lzcpu_destroy_wrapper)(void *);
extern bool need_new_vmid_gen(struct kvm_vmid *vmid);
extern void kvm_arm_vmid_update(struct kvm_vmid *kvm_vmid);
extern pte_t huge_ptep_get(pte_t *ptep);

/* LightZone use some non-exported kvm symbols */
#define IMPORT_SYMBOL_VALUE_FOR___boot_cpu_mode							(0xffff800012349800UL)
#define IMPORT_SYMBOL_VALUE_FOR_sys_call_table							(0xffff800011001678UL)
#define IMPORT_SYMBOL_VALUE_FOR_vectors									(0xffff800010010800UL)
#define IMPORT_SYMBOL_VALUE_FOR_do_group_exit							(0xffff8000100960a4UL)
#define IMPORT_SYMBOL_VALUE_FOR_kernel_clone							(0xffff80001008cf50UL)
#define IMPORT_SYMBOL_VALUE_FOR_fpsimd_restore_current_state			(0xffff800010015ae0UL)
#define IMPORT_SYMBOL_VALUE_FOR_mem_cgroup_handle_over_high				(0xffff8000102f4ac0UL)
#define IMPORT_SYMBOL_VALUE_FOR_task_work_run							(0xffff8000100baec4UL)
#define IMPORT_SYMBOL_VALUE_FOR_blkcg_maybe_throttle_current			(0xffff8000105999c4UL)
#define IMPORT_SYMBOL_VALUE_FOR___rseq_handle_notify_resume				(0xffff8000102347e4UL)
#define IMPORT_SYMBOL_VALUE_FOR_do_signal								(0xffff80001001c210UL)
#define IMPORT_SYMBOL_VALUE_FOR_expand_stack							(0xffff800010290770UL)
#define IMPORT_SYMBOL_VALUE_FOR_lzcpu_destroy_wrapper					(0xffff800012357858UL)
#define IMPORT_SYMBOL_VALUE_FOR_update_vmid								(0xffff800010050420UL)
#define IMPORT_SYMBOL_VALUE_FOR_need_new_vmid_gen						(0xffff800010050400UL)
#define IMPORT_SYMBOL_VALUE_FOR_kvm_arm_vmid_update						(0x0UL)
#define IMPORT_SYMBOL_VALUE_FOR_huge_ptep_get							(0x0UL)
#define IMPORT_SYMBOL_VALUE_FOR_lzhcr_check_update						(0xffff800012355400UL)

#define IMPORT_SYMBOL(name) \
	static typeof(&name) IMPORTED(name) __attribute__((unused)) = (typeof(&name))IMPORT_SYMBOL_VALUE_FOR_ ## name
#define IMPORTED(name) __i__ ## name

IMPORT_SYMBOL(lzcpu_destroy_wrapper);
IMPORT_SYMBOL(lzhcr_check_update);

/* For module load and PTE. */
IMPORT_SYMBOL(__boot_cpu_mode);
IMPORT_SYMBOL(do_signal);
IMPORT_SYMBOL(huge_ptep_get);

/* For unique VMID allocation. */
IMPORT_SYMBOL(kvm_arm_vmid_update);
IMPORT_SYMBOL(update_vmid);
IMPORT_SYMBOL(need_new_vmid_gen);

/* For syscalls and VBAR. */
IMPORT_SYMBOL(sys_call_table);
IMPORT_SYMBOL(vectors);

/* For system calls. */
IMPORT_SYMBOL(do_group_exit);
IMPORT_SYMBOL(kernel_clone);

/* For prepare exit to user. */
IMPORT_SYMBOL(fpsimd_restore_current_state);

/* For copied_resume_user_mode_work. */
IMPORT_SYMBOL(mem_cgroup_handle_over_high);
IMPORT_SYMBOL(task_work_run);
IMPORT_SYMBOL(blkcg_maybe_throttle_current);
IMPORT_SYMBOL(__rseq_handle_notify_resume);
IMPORT_SYMBOL(expand_stack);

/************************************
 ************************************
 ********** For LowVisor Only *******
 ************************************
 ************************************/

extern void (*lightzone_lowvisor_ops_wp)(struct kvm *);
extern void (*lightzone_lowvisor_ops_flush)(struct kvm *, struct kvm_memory_slot *);
extern void (*lightzone_lowvisor_ops_clear)(struct kvm *);
extern bool lightzone_lowvisor_ops_valid;
typedef bool (*exit_handler_fn)(struct kvm_vcpu *, u64 *);
typedef int (*exit_handle_fn)(struct kvm_vcpu *);
extern bool (*lightzone_lowvisor_early_handler)(struct kvm_vcpu *, u64 *);
extern exit_handle_fn arm_exit_handlers[];
extern exit_handler_fn hyp_exit_handlers[];
extern struct file_operations kvm_vm_fops;
extern struct file_operations kvm_vcpu_fops;
extern u32 get_kvm_ipa_limit(void);
extern unsigned long gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot, gfn_t gfn, bool *writable);
int kvm_handle_guest_abort(struct kvm_vcpu *vcpu);

#define IMPORT_SYMBOL_VALUE_FOR_kvm_handle_guest_abort					(0xffff800010053aa0UL)
#define IMPORT_SYMBOL_VALUE_FOR_lightzone_lowvisor_ops_wp				(0xffff8000123561b0UL)
#define IMPORT_SYMBOL_VALUE_FOR_lightzone_lowvisor_ops_flush			(0xffff8000123561a8UL)
#define IMPORT_SYMBOL_VALUE_FOR_lightzone_lowvisor_ops_clear			(0xffff800012356190UL)
#define IMPORT_SYMBOL_VALUE_FOR_lightzone_lowvisor_ops_valid			(0xffff800012356188UL)
#define IMPORT_SYMBOL_VALUE_FOR_lightzone_lowvisor_early_handler		(0xffff8000123562c8UL)
#define IMPORT_SYMBOL_VALUE_FOR_arm_exit_handlers						(0xffff80001100b670UL)
#define IMPORT_SYMBOL_VALUE_FOR_kvm_vm_fops								(0xffff800011f71188UL)
#define IMPORT_SYMBOL_VALUE_FOR_kvm_vcpu_fops							(0xffff800011f71288UL)
#define IMPORT_SYMBOL_VALUE_FOR_get_kvm_ipa_limit						(0xffff80001005cd50UL)
#define IMPORT_SYMBOL_VALUE_FOR_gfn_to_hva_memslot_prot					(0xffff800010046e30UL)
#define IMPORT_SYMBOL_VALUE_FOR_hyp_exit_handlers						(0x0UL)

IMPORT_SYMBOL(kvm_handle_guest_abort);
IMPORT_SYMBOL(lightzone_lowvisor_ops_wp);
IMPORT_SYMBOL(lightzone_lowvisor_ops_flush);
IMPORT_SYMBOL(lightzone_lowvisor_ops_clear);
IMPORT_SYMBOL(lightzone_lowvisor_ops_valid);
IMPORT_SYMBOL(lightzone_lowvisor_early_handler);
IMPORT_SYMBOL(arm_exit_handlers);
IMPORT_SYMBOL(kvm_vm_fops);
IMPORT_SYMBOL(kvm_vcpu_fops);
IMPORT_SYMBOL(get_kvm_ipa_limit);
IMPORT_SYMBOL(gfn_to_hva_memslot_prot);
IMPORT_SYMBOL(hyp_exit_handlers);

#endif