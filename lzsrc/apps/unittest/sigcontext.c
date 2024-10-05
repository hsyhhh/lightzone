#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <liblz.h>

int *gmem;
void sig_handler(int signo);
int main(void)
{
#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif
    printf("main is waiting for a signal\n");

#ifdef LZ_SCALABLE
    int *mem = (int *)memalign(4096, 4096);
    int lz_1 = lz_alloc();
	lz_set_glz(lz_1, 0);
	printf("The lz 1 is %d\n", lz_1);
    lz_mprotect((unsigned long)mem, 4096, lz_1, LZ_PROT_READ | LZ_PROT_WRITE);

    gmem = (int *)memalign(4096, 4096);
    int lz_2 = lz_alloc();
	lz_set_glz(lz_2, 1);
	printf("The lz 2 is %d\n", lz_2);
    lz_mprotect((unsigned long)gmem, 4096, lz_2, LZ_PROT_READ | LZ_PROT_WRITE);

    int *newmem = (int *)memalign(4096, 4096);
    int lz_3 = lz_alloc();
	lz_set_glz(lz_3, 2);
	printf("The lz 3 is %d\n", lz_3);
    lz_mprotect((unsigned long)newmem, 4096, lz_3, LZ_PROT_READ | LZ_PROT_WRITE);
#else
    gmem = (int *)memalign(4096, 4096);
    int lz_1 = lz_alloc();
	printf("The lz 1 is %d\n", lz_1);
    lz_mprotect((unsigned long)gmem, 4096, lz_1, LZ_PROT_READ | LZ_PROT_WRITE);
#endif

    __sighandler_t prehandler;
    prehandler = signal(SIGINT,sig_handler);
    if(prehandler == SIG_ERR){
        perror("signal errror");
        exit(EXIT_FAILURE);
    }

    printf("the previous value of the signal handler is %lx\n", (unsigned long)prehandler);
    while (1) {
#ifdef LZ_SCALABLE
        lz_switch_to_gate(0);
        mem[0]++;
        lz_switch_to_gate(2);
        newmem[2]++;
#else
        lz_switch_to_norm();
#endif
    }

    return 0;
}

void sig_handler(int signo)
{
#ifdef LZ_SCALABLE
    lz_switch_to_gate(1);
#else
    lz_switch_to_prot();
#endif
    printf("catch the signal SIGINT %d, %d\n",signo, gmem[0]++);
}
