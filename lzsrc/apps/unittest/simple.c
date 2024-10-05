#include <liblz.h>
#include <stdio.h>

#define PAGE_SIZE 4096

int fib (int i) {
	// asm volatile ("mov x8, xzr\n\t\
                        // add x8, x8, #172\n\t\
                        // svc #0":::"memory");

	if (i == 1 || i == 0)
		return 1;
	return fib(i - 1) + fib(i - 2);
}

int main() {
    char *page_1 = (char *)memalign(PAGE_SIZE, PAGE_SIZE);
        char *page_2 = (char *)memalign(PAGE_SIZE, PAGE_SIZE);
        int i;
	float f1, f2;
        for(i = 0; i < PAGE_SIZE; i++) {
                page_1[i] = (char)i;
                page_1[i] = (char)i;
        }
        printf("The page 1 is %lx\n", (unsigned long)page_1);

#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif

        for(i = 0; i < PAGE_SIZE; i++) {
                page_1[i] = (char)i;
                page_1[i] = (char)i;
        }

	printf("Hello LightZone!\n");
	scanf("%f%f", &f1, &f2);
	printf("%f + %f = %f\n", f1, f2, f1 + f2);
	printf("Now return the program.\n");
	
	return PAGE_SIZE;
}
