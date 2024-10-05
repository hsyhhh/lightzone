/**
 * main.c - the entry to read-write the LightZone code
 *
 *
 * Authors:
 *   Ziqi Yuan   <yuanzqss@zju.edu.cn>
 */
#include <linux/spinlock.h>
#include <linux/list.h>
#include <asm/syscall.h>
#include <linux/userfaultfd_k.h>

#include "lightzone.h"
#include "pt.h"
#include "lzarm.h"
#include "lzcpu.h"
#include "paravirt.h"
#include "lzsym.h"

extern int max_available_asids;

LIST_HEAD(glzcpus);
LIST_HEAD(glzprocs);
struct rw_semaphore big_lz_lock;

static lzrange_t *find_first_lzrange(int zoneid, lzproc_t *proc)
{
	struct rb_node *node;
	lzrange_t *data;
	int zone_idx;

	for (node = rb_first(&proc->lzrange); node; node = rb_next(node)) {
		data = rb_entry(node, lzrange_t, node);
		for (zone_idx = 0; zone_idx < 4; zone_idx++)
			if (data->zoneid[zone_idx] == zoneid)
				return data;
	}
	return NULL;
}

void erase_free_lzrange(lzrange_t *range, lzproc_t *proc)
{
	if (range) {
		rb_erase(&range->node, &proc->lzrange);
		kfree(range);
	}
}

static bool find_and_insert_lzrange(unsigned long addr, size_t len, int zoneid, 
						int prot, lzproc_t *proc, lzrange_t *data)
{
	lzrange_t *this;
	int zone_idx, lev;
	bool already_exists = false;
	struct rb_root *root = &proc->lzrange;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	unsigned long end = addr + len;

	/* Figure out where to put new node */
	while (*new) {
		this = rb_entry(*new, lzrange_t, node);
		parent = *new;
		if (addr < this->start && end <= this->start)
			new = &((*new)->rb_left);
		else if (addr > this->start && addr >= this->end)
			new = &((*new)->rb_right);
		else if (addr == this->start && end == this->end) {
			already_exists = true;
			break;
		} else {
			kfree(data);
			return false;
		}
	}

	if (already_exists) {
		bool zoneid_found = false;
		for (zone_idx = 0; zone_idx < 4; zone_idx++) {
			if (this->zoneid[zone_idx] == zoneid) {
				this->perm[zone_idx] = prot;
				zoneid_found = true;
			}
			if (zoneid == NOPROT_LZID)
				this->zoneid[zone_idx] = zoneid;
		}
		if (!zoneid_found) {
			for (zone_idx = 0; zone_idx < 4; zone_idx++) {
				if (this->zoneid[zone_idx] == NOPROT_LZID) {
					this->zoneid[zone_idx] = zoneid;
					this->perm[zone_idx] = prot;
					break;
				}
			}
			if (zone_idx == 4) {
				this->zoneid[0] = zoneid;
				this->perm[0] = prot;
			}
		}
	} else if (zoneid != NOPROT_LZID) {
		if (!data)
			return false;
		for (zone_idx = 1; zone_idx < 4; zone_idx++)
			data->zoneid[zone_idx] = NOPROT_LZID;
		data->zoneid[0] = zoneid;
		data->perm[0] = prot;
		data->start = addr;
		data->end = end;
		rb_link_node(&data->node, parent, new);
		rb_insert_color(&data->node, root);
	}

	if (already_exists)	{	/* No domain needs this range anymore */
		for (zone_idx = 0; zone_idx < 4; zone_idx++)
			if (this->zoneid[zone_idx] != NOPROT_LZID)
				break;
		if (zone_idx >= 4)
			erase_free_lzrange(this, proc);
	}

	if (data && (zoneid == NOPROT_LZID || already_exists))
		kfree(data);

	for (; addr < end;) {
		pt_inv_page(proc, addr, &lev);
		switch (lev) {
			case 0: addr += PAGE_SIZE; break;
			case 1: addr += PAGE_SIZE * PTRS_PER_PTE; break;
			case 2: addr += PAGE_SIZE * PTRS_PER_PTE * PTRS_PER_PTE; break;
			default: addr += PAGE_SIZE * PTRS_PER_PTE * PTRS_PER_PTE * PTRS_PER_PTE;
		}
	}

	PV_lz_flush_tlb_by_vmid_s1(proc, 0);
	return true;
}

static void lz_sys_exit_group_wrapper(void)
{
	extern int lz_sys_exit_group(struct pt_regs *regs);
	struct pt_regs *regs = current_pt_regs();
	regs->regs[0]   = 0;
	regs->regs[8]   = __NR_exit_group;
	regs->orig_x0   = (unsigned long)get_current_lzcpu();
	regs->syscallno = __NR_exit_group;
	lz_sys_exit_group(regs);
}

int lz_alloc(lzproc_t *proc)
{
	int i, rc;
	unsigned long ttbr0;
	unsigned long __user *tab;

	mmap_write_lock(proc->host_mm);
	spin_lock(&proc->proc_lock);
	ttbr0 = proc->default_ttbr0;
	i = find_first_zero_bit(proc->zone_bm, NR_LZID);
	tab = (unsigned long *)proc->ttbr0_tab_start;
	if (i != NR_LZID && i < max_available_asids &&
		proc->ttbr0_tab_start + 8 * i < proc->ttbr0_tab_end) {
		set_bit(i, proc->zone_bm);
		tab = (unsigned long *)(proc->ttbr0_tab_start + sizeof(unsigned long) * i);
	} else
		i = -1;
	spin_unlock(&proc->proc_lock);
	if (i > 0)
		rc = lz_init_stage1_mmu(proc, (u64)i, &ttbr0);
	else
		rc = 0;
	mmap_write_unlock(proc->host_mm);
	if (rc || (i >= 0 && put_user(ttbr0, tab)))
		lz_sys_exit_group_wrapper();
	return i;
}

void lz_free(int zoneid, lzcpu_t *lzcpu)
{
	lzrange_t *range;
	unsigned long __user *tab;
	lzproc_t *proc = lzcpu->proc;
	bool was_active_zone = false, uaf = false;

	spin_lock(&proc->proc_lock);
	tab = (unsigned long *)proc->ttbr0_tab_start;
	if (zoneid >= 0 && zoneid < NR_LZID && zoneid < max_available_asids &&
			proc->ttbr0_tab_start + 8 * zoneid < proc->ttbr0_tab_end) {
		was_active_zone = test_and_clear_bit(zoneid, proc->zone_bm);
		tab = (unsigned long *)(proc->ttbr0_tab_start + sizeof(unsigned long) * zoneid);
		if (was_active_zone) {
			if (zoneid) {
				lz_free_stage1_mmu(proc, zoneid);
				if (((lzcpu->ttbr0 & TTBR_ASID_MASK) >> USER_ASID_BIT) == zoneid) {
					lzcpu->ttbr0 = proc->default_ttbr0;
					current_pt_regs()->pstate |= PSR_PAN_BIT;
				}
			}
			while ((range = find_first_lzrange(zoneid, proc))) {
				uaf = true;
				erase_free_lzrange(range, proc);
			}
		}
	}
	spin_unlock(&proc->proc_lock);

	if (uaf) {
		printk(KERN_ERR "lightzone: User frees zone %d with protected memory\n", zoneid);
		lz_sys_exit_group_wrapper();
	}

	if (put_user((u64)0, tab))
		lz_sys_exit_group_wrapper();
}

int lz_mprotect(unsigned long addr, size_t len, int zoneid, int prot, lzproc_t *proc)
{
	lzrange_t *data;
	int rc = -EINVAL;
	
	if (zoneid < -1 || zoneid >= max_available_asids || zoneid >= NR_LZID)
		return rc;
	if ((prot & LZ_PROT_DEF) != (LZ_PROT_READ) &&								/* R 	*/
		(prot & LZ_PROT_DEF) != (LZ_PROT_READ | LZ_PROT_WRITE) &&				/* RW	*/
		(prot & LZ_PROT_DEF) != (LZ_PROT_READ | LZ_PROT_EXEC) &&				/* RX	*/
		(prot & LZ_PROT_DEF) != (LZ_PROT_READ | LZ_PROT_WRITE | LZ_PROT_EXEC))	/* RWX	*/
		return rc;
	addr &= PAGE_MASK;
	len &= PAGE_MASK;
	if (addr >= addr + len)
		return rc;

	data = kzalloc(sizeof(lzrange_t), GFP_KERNEL);	/* NULL is OK here. */
	
	spin_lock(&proc->proc_lock);
	if (zoneid == NOPROT_LZID || test_bit(zoneid, proc->zone_bm)) {
		/* 
		* Currently, if there is address overlap, just return -EINVAL.
		* Perhaps complicated VMA-merge-split-alike if needed?
		*/
		if (find_and_insert_lzrange(addr, len, zoneid, prot, proc, data)) {
			rc = 0;
			PV_lz_flush_tlb_by_vmid_s1(proc, 0);
		}
	} else if (data)
		kfree(data);
	spin_unlock(&proc->proc_lock);

	return rc;
}

int lz_bind_call_site(lzproc_t *proc, int gateid, unsigned long retaddr)
{
	struct page *page;
	unsigned long *kernel_retaddr;
	unsigned long offset = sizeof(lz_per_gate_t) * gateid;
	struct page **pages = proc->per_gate_pages;

	if (offset + proc->call_gate_start >= proc->per_gate_end)
		return -EINVAL;
	
	if (!pages) {
		if (lz_gate_tab_init(proc))
			return -EINVAL;
		pages = proc->per_gate_pages;
	}

	page = pages[offset / PAGE_SIZE];
	offset &= ~PAGE_MASK;
	if (!page)
		return -EINVAL;
	kernel_retaddr = (unsigned long *)(page_to_virt(page) + ((unsigned long)(&((lz_per_gate_t *)offset)->retaddr)));
	*kernel_retaddr = retaddr;
	return 0;
}

int lz_set_glz(int gateid, int zoneid, lzproc_t *proc)
{
	lz_per_gate_t data;
	lz_per_gate_t __user *tab;

	if (zoneid < 0 || zoneid >= max_available_asids || zoneid >= NR_LZID)
		return -EINVAL;
	if (gateid * sizeof(lz_per_gate_t) + proc->call_gate_start >= proc->per_gate_end)
		return -EINVAL;

	/* Letting users handle the concurrency problem is fine. */
	tab = (lz_per_gate_t *)proc->per_gate_start + gateid;
	if (copy_from_user(&data, tab, sizeof(lz_per_gate_t)))
		return -EIO;

	if (data.zoneid != NOPROT_LZID) {
		printk(KERN_ERR "lightzone: The attacker tries to bind a call gate to different zoneid and ret addr.\n");
		return -EINVAL;
	}

	data.zoneid = zoneid;

	if (copy_to_user(tab, &data, sizeof(lz_per_gate_t)))
		return -EIO;
	return 0;	
}
