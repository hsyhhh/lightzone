#define LZDEBUG
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#include <liblz.h>
#include <stdio.h>

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

unsigned long ccnt_read(void)
{
	unsigned long cnt;

	asm volatile("isb\n mrs %0, pmccntr_el0\n"
				 "nop\n"
		     : "=r" (cnt));
	arch_counter_enforce_ordering(cnt);
	return cnt;
}

static inline void system_svc(void)
{
    asm volatile("mov x8, %0\n svc #0\n"
		     :: "r" (0xffffffffUL) : "memory", "x8");
}

static inline void prtpmu(void)
{
	unsigned long pmcr, pmcn, pmu, pmcc;
	
	asm volatile("mrs %0, pmcr_el0\n\t"
				 "mrs %1, pmcntenset_el0\n\t"
				 "mrs %2, pmuserenr_el0\n\t"
				 "mrs %3, pmccfiltr_el0\n\t"
				 "nop\n" ::
				 "r" (pmcr),
				 "r" (pmcn), "r" (pmu), "r" (pmcc) : "memory");
	
	printf("pmcr %lx, pmcn %lx, pmu %lx, pmcc %lx\n", pmcr, pmcn, pmu, pmcc);
}

int main() {
    int iter = 1000;
    unsigned long start, end, baseline;

	int i;

    printf("Begin counting switch\n");

	system_svc();
	activate_counter();
    start = ccnt_read();
    for (i = 0; i < iter; i++)
        system_svc();
    end = ccnt_read();

	printf("End counting switch, %ld cycles per svc\n", 
            (baseline = (end - start) / iter));

#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif
	sleep(1);

    printf("Begin counting switch\n");

	system_svc();
	activate_counter();
    start = ccnt_read();
    for (i = 0; i < iter; i++) {
        system_svc();
    }
    end = ccnt_read();

    /* 526 in QEMU, too bad */
	printf("End counting switch, %ld cycles per hyp svc\n", (end - start) / iter);
	return 0;
}