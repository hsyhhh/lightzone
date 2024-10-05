#include <liblz.h>
#include <stdio.h>
#include <unistd.h>

int main() {
#ifdef LZ_SCALABLE
    lz_enter(true);
#else
    lz_enter(false);
#endif

    pid_t PID = fork();

    switch(PID){
        case -1:
            perror("fork()");
            exit(-1);
        
        case 0:
            printf("I'm Child process\n");
            printf("Child's PID is %d\n", getpid());
            break;
        
        default:
            printf("I'm Parent process\n");
            printf("Parent's PID is %d\n", getpid());
    }
	
	return 0;
}
