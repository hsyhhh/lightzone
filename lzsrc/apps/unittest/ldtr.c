#include <stdio.h>
#include <liblz.h>

#define SCS_SIZE (8 * 4096)

int main() {
	char *scs = (char *)mmap(NULL, SCS_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	*scs = '1';
	printf("scs addr: %llx\n", (unsigned long long)scs);

	int lz_ret = lz_enter(false);
    printf("[FAST_LIGHTZONE] lz_enter with ret: %d\n", lz_ret);
    lz_alloc();
    lz_mprotect((unsigned long)scs, SCS_SIZE, 0, LZ_PROT_READ | LZ_PROT_WRITE);
    lz_switch_to_norm();
	__asm__ __volatile__("ldtr x10, [%0]" ::"r"(scs));
	printf("success!\n");
	return 0;
}