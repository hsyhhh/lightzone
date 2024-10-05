#define LZDEBUG
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#include <liblz.h>
#include <stdio.h>

int main() {
	int *page_1 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_2 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_3 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);
	int *page_4 = (int *)memalign(PAGE_SIZE, PAGE_SIZE);

	int i;
	int op;

	for(i = 0; i < PAGE_SIZE / sizeof(int); i++) {
		page_1[i] = i + 1;
		page_2[i] = i + 2;
		page_3[i] = i + 3;
		page_4[i] = i + 4;
	}
	printf("The page 1 is %lx\n", (unsigned long)page_1);
	printf("The page 2 is %lx\n", (unsigned long)page_2);
	printf("The page 3 is %lx\n", (unsigned long)page_3);
	printf("The page 4 is %lx\n", (unsigned long)page_4);

#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif

	printf("Please enter the OP, 0 for legal, 1 for violation, 2 for domain-UAF, 3 for PAN:\n");
	scanf("%d", &op);
	op = op % 4;

#ifdef LZ_SCALABLE
	int lz_1 = lz_alloc();
	lz_set_glz(lz_1, 0);
	printf("The lz 1 is %d\n", lz_1);
	int lz_2 = lz_alloc();
	lz_set_glz(lz_2, 1);
	printf("The lz 2 is %d\n", lz_2);
	int lz_3 = lz_alloc();
	lz_set_glz(lz_3, 2);
	lz_set_glz(lz_3, 4);
	lz_set_glz(lz_3, 5);
	printf("The lz 3 is %d\n", lz_3);
	int lz_4 = lz_alloc();
	lz_set_glz(lz_4, 3);
	printf("The lz 4 is %d\n", lz_4);

	lz_mprotect((unsigned long)page_1, PAGE_SIZE, lz_1, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_2, PAGE_SIZE, lz_2, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_3, PAGE_SIZE, lz_3, LZ_PROT_READ | LZ_PROT_WRITE);
	lz_mprotect((unsigned long)page_4, PAGE_SIZE, lz_4, LZ_PROT_READ | LZ_PROT_WRITE);

	printf("Finished lz_mprotect\n");
	sleep(1);

	lz_switch_to_gate(0);
	page_1[16] = -page_1[16];
	printf("The accessed page_1[16] = %d\n", page_1[16]);

	lz_switch_to_gate(1);
	page_2[32] = -page_2[32];
	printf("The accessed page_2[32] = %d\n", page_2[32]);

	lz_switch_to_gate(2);
	page_3[64] = -page_3[64];
	printf("The accessed page_3[64] = %d\n", page_3[64]);

	lz_switch_to_gate(3);
	page_4[8] = -page_4[8];
	printf("The accessed page_4[8] = %d\n", page_4[8]);

	lz_switch_to_gate(4);
	printf("Now switch to lz_3\n");

	lz_mprotect((unsigned long)page_1, PAGE_SIZE, -1, LZ_PROT_READ | LZ_PROT_WRITE);
	printf("lz_mprotect -1 for page_1\n");
	page_1[63] = -page_1[63];
	printf("The accessed page_1[63] = %d\n", page_1[63]);
	lz_free(lz_1);

	// TEST VIOLATION, TEST UAF * 2, TEST PAN

	// TEST VIOLATION
	if (op == 1) {
		printf("Now in lz_3, I want illegal access to page_2...\n");
		page_2[11] = -page_2[11];
		printf("The accessed page_2[11] = %d\n", page_2[11]);
	} else if (op == 2) {
		lz_free(lz_3);
		printf("lz_3 freed. Now the kernel has it to default zone with least privilige. \
			 Do you want to switch to lz_3 (1) or direct access (0)? Both should fail.\n");
		int uop;
		scanf("%d", &uop);
		if (uop % 2) {
			lz_switch_to_gate(5);
			printf("SWITCH ERROR DETECTED!!!\n");
		}
		page_3[11] = -page_3[11];
		printf("The accessed page_3[11] = %d with UAF, the kernel should warn\n", page_3[11]);
		return 0;
	} else if (op == 3) {
		lz_switch_to_norm();
		printf("Now switch to -1\n");
		printf("Now in lz_3 -> lz_-1, I want illegal access to page_3...\n");
		page_3[61] = -page_3[61];
		printf("The accessed page_3[61] = %d\n", page_3[61]);
	}
	
	if (op)
		printf("ERROR DETECTED!!!\n");
#else
	int lz_1 = lz_alloc();
	printf("The lz 1 is %d\n", lz_1);

	lz_mprotect((unsigned long)page_1, PAGE_SIZE, lz_1, LZ_PROT_READ | LZ_PROT_WRITE);

	lz_switch_to_prot();
	printf("switch to prot first, page1[16] is %d\n", page_1[16]);

	lz_switch_to_norm();
	printf("now switch to norm, should crash\n");
	sleep(1);
	printf("switch to norm first, page1[16] is %d\n", page_1[17]);

	printf("ERROR DETECTED!!!\n");
#endif
	return 0;
}