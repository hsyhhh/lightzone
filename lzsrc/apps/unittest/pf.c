#define LZDEBUG
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#include <liblz.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

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

int main() {
	int *page_1 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_2 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_3 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_4 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);

    unsigned long start, end;
	unsigned long pf_origin, pf_lzone;

	page_3[0] = 1234;
	activate_counter();
	start = ccnt_read();
    page_1[0] = 1234;
    end = ccnt_read();
	pf_origin = end - start;

#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif

	page_4[0] = 1234;
	activate_counter();
	start = ccnt_read();
    page_2[0] = 1234;
    end = ccnt_read();
	pf_lzone = end - start;

	printf("%lu\n", 
            pf_origin);
	printf("%lu\n", 
            pf_lzone);

	return 0;
}