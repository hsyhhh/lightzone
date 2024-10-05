#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <liblz.h>

void sig_handler(int signo);
int main(void)
{
#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif
    printf("main is waiting for a signal\n");
    __sighandler_t prehandler;
    prehandler = signal(SIGINT,sig_handler);
    if(prehandler == SIG_ERR){
        perror("signal errror");
        exit(EXIT_FAILURE);
    }

    printf("the previous value of the signal handler is %lx\n", (unsigned long)prehandler);
    while (1) {}


    return 0;
}

void sig_handler(int signo)
{
    printf("catch the signal SIGINT %d\n",signo);
}
