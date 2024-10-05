#define LZDEBUG
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#include <liblz.h>
#include <stdio.h>
#include <sys/time.h>

#define arch_counter_enforce_ordering(val) do {				\
	unsigned long tmp, _val = (val);						\
									\
	asm volatile(							\
	"	eor	%0, %1, %1\n"					\
	"	add	%0, sp, %0\n"					\
	"	ldr	xzr, [%0]"					\
	: "=r" (tmp) : "r" (_val));					\
} while (0)

#define ARMV8_PMCR_LC		(1UL << 6)
#define ARMV8_PMCR_E		(1UL << 0)

void activate_counter(void)
{
	asm volatile("msr pmcr_el0, %0\n\t"
				 "nop\n" :: "r" (ARMV8_PMCR_LC | ARMV8_PMCR_E) : "memory");
}

unsigned long pmcr_el0(void)
{
	unsigned long cnt;

	asm volatile("isb\n mrs %0, pmcr_el0\n"
				 "nop\n"
		     : "=r" (cnt));
	arch_counter_enforce_ordering(cnt);
	return cnt;
}

unsigned long pmcntenset_el0(void)
{
	unsigned long cnt;

	asm volatile("isb\n mrs %0, pmcntenset_el0\n"
				 "nop\n"
		     : "=r" (cnt));
	arch_counter_enforce_ordering(cnt);
	return cnt;
}

unsigned long pmuserenr_el0(void)
{
	unsigned long cnt;

	asm volatile("isb\n mrs %0, pmuserenr_el0\n"
				 "nop\n"
		     : "=r" (cnt));
	arch_counter_enforce_ordering(cnt);
	return cnt;
}

unsigned long ccnt_read(void)
{
	unsigned long cnt;

	asm volatile("isb\n mrs %0, pmccntr_el0\n"
				 "nop\n"
		     : "=r" (cnt));
	arch_counter_enforce_ordering(cnt);
	return cnt;
}

int main(void) {
    int *page_10 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_11 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_12 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_13 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_14 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_15 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_16 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_17 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_18 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_19 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_20 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_21 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_22 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_23 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_24 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_25 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_26 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_27 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_28 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
    int *page_29 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);


    unsigned long start, end;
    int i;

	activate_counter();
	start = ccnt_read();
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_10[i] = -page_10[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_11[i] = -page_11[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_12[i] = -page_12[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_13[i] = -page_13[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_14[i] = -page_14[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_15[i] = -page_15[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_16[i] = -page_16[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_17[i] = -page_17[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_18[i] = -page_18[i];
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_19[i] = -page_19[i];
    end = ccnt_read();

	printf("norm %lu\n", 
            end - start);

    lz_enter(true);

    int lz0 = lz_alloc();
    int lz1 = lz_alloc();
    int lz2 = lz_alloc();
    int lz3 = lz_alloc();
    int lz4 = lz_alloc();
    int lz5 = lz_alloc();
    int lz6 = lz_alloc();
    int lz7 = lz_alloc();
    int lz8 = lz_alloc();
    int lz9 = lz_alloc();

    lz_set_glz(lz0, 0);
    lz_set_glz(lz1, 1);
    lz_set_glz(lz2, 2);
    lz_set_glz(lz3, 3);
    lz_set_glz(lz4, 4);
    lz_set_glz(lz5, 5);
    lz_set_glz(lz6, 6);
    lz_set_glz(lz7, 7);
    lz_set_glz(lz8, 8);
    lz_set_glz(lz9, 9);

    lz_mprotect((unsigned long)page_20, PAGE_SIZE, lz0, LZ_PROT_READ | LZ_PROT_WRITE);
    lz_mprotect((unsigned long)page_21, PAGE_SIZE, lz1, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_22, PAGE_SIZE, lz2, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_23, PAGE_SIZE, lz3, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_24, PAGE_SIZE, lz4, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_25, PAGE_SIZE, lz5, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_26, PAGE_SIZE, lz6, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_27, PAGE_SIZE, lz7, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_28, PAGE_SIZE, lz8, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_29, PAGE_SIZE, lz9, LZ_PROT_READ | LZ_PROT_WRITE);

    activate_counter();
	start = ccnt_read();
    lz_switch_to_gate(0);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_20[i] = -page_20[i];
    lz_switch_to_gate(1);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_21[i] = -page_21[i];
    lz_switch_to_gate(2);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_22[i] = -page_22[i];
    lz_switch_to_gate(3);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_23[i] = -page_23[i];
    lz_switch_to_gate(4);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_24[i] = -page_24[i];
    lz_switch_to_gate(5);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_25[i] = -page_25[i];
    lz_switch_to_gate(6);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_26[i] = -page_26[i];
    lz_switch_to_gate(7);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_27[i] = -page_27[i];
    lz_switch_to_gate(8);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_28[i] = -page_28[i];
    lz_switch_to_gate(9);
    for (i = 0; i < 4096 / sizeof(int); i++)
        page_29[i] = -page_29[i];
    end = ccnt_read();

	printf("norm %lu\n", 
            end - start);

	return 0;
}