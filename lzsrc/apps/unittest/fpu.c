#include <pthread.h>
#include <stdio.h>
#include <liblz.h>
// a simple pthread example 
// compile with -lpthreads

// create the function to be executed as a thread

#define ARMV8_PMCR_LC		(1UL << 6)
#define ARMV8_PMCR_E		(1UL << 0)

pthread_mutex_t mutex;
long counter = 0;

void activate_counter(void)
{
	asm volatile("msr pmcr_el0, %0\n\t"
				 "nop\n" :: "r" (ARMV8_PMCR_LC | ARMV8_PMCR_E) : "memory");
}

void lz_switch_to_gate_wrapper(int gate)
{
    switch (gate) {
        case 0:     lz_switch_to_gate(0); break;
        case 1:     lz_switch_to_gate(1); break;
        case 2:     lz_switch_to_gate(2); break;
        case 3:     lz_switch_to_gate(3); break;
        case 4:     lz_switch_to_gate(4); break;
        case 5:     lz_switch_to_gate(5); break;
        case 6:     lz_switch_to_gate(6); break;
        case 7:     lz_switch_to_gate(7); break;
        case 8:     lz_switch_to_gate(8); break;
        case 9:     lz_switch_to_gate(9); break;
        case 10:    lz_switch_to_gate(10); break;
        case 11:    lz_switch_to_gate(11); break;
        case 12:    lz_switch_to_gate(12); break;
        case 13:    lz_switch_to_gate(13); break;
        case 14:    lz_switch_to_gate(14); break;
        case 15:    lz_switch_to_gate(15); break;
    }
}

void *thread(void *tp)
{
    int tid = (int)tp;

#ifdef LZ_SCALABLE
    lz_switch_to_gate_wrapper(tid);
#endif

    activate_counter();
    
    printf("Thread - %d\n",tid);

    double fsum = 0;
    int i;

    for (i = 0; i < 10000000; i++) {
        pthread_mutex_lock(&mutex);
        counter++;
        pthread_mutex_unlock(&mutex);
        if (i < 1000000)
            fsum += 0.0000001 * i;
        else
            fsum += 0.000000001 * i;
    }
    printf("Thread[%d] fsum is %f\n", tid, fsum);
    return NULL;
}

int main(int argc, char **argv)
{
    int i;
#ifdef LZ_SCALABLE
    lz_enter(true);
    int lz[16];
    for (i = 0; i < 16; i++) {
        lz[i] = lz_alloc();
        lz_set_glz(lz[i], i);
    }
#else
    lz_enter(false);
#endif
    // create the thread objs
    pthread_t threads[16];

    pthread_mutex_init(&mutex, NULL);
    
    for (i = 0; i < 16; i++)
        pthread_create(&threads[i], NULL, *thread, (void *)i);

    thread((void *)-1);

    // wait for threads to finish
    for (i = 0; i < 16; i++)
        pthread_join(threads[i], NULL);
    printf("counter is %ld\n", counter);
    return 0;
}