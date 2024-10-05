#include <liblz.h>
#include <stdio.h>

#define PAGE_SIZE 4096

int main() {

#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif

        char *page_1 = (char *)memalign(PAGE_SIZE, PAGE_SIZE);
        char *page_2 = (char *)memalign(PAGE_SIZE, PAGE_SIZE);
        int i;
        for(i = 0; i < PAGE_SIZE; i++) {
                page_1[i] = (char)i;
                page_2[i] = (char)i;
        }
        printf("The page 1 is %lx\n", (unsigned long)page_1);

        for(i = 0; i < PAGE_SIZE; i++) {
                page_1[i] = (char)i;
                page_2[i] = (char)i;
        }

	printf("Unmapping page_1!\n");
	
        munmap(page_1, PAGE_SIZE);

        printf("Trying to access the unmapped page_1, should trigger page fault!\n");

        sleep(1);

        printf("The value of page_1[i] is %c\n", page_1[0] + '0');
	
	return PAGE_SIZE;
}
