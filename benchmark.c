#include <stdio.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <sys/resource.h>
#include "pskdh.h"

void test_function()
{
    int calc = pow(25, 2);
}

int main()
{
    struct rusage usage;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // sleep(5);
    psk_dh();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Execution time: %f seconds\n", time_taken);

    getrusage(RUSAGE_SELF, &usage);
    printf("Memory usage: %ld KB\n", usage.ru_maxrss);

    return 0;
}


// To run it
// gcc pskdh.c -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto benchmark.c -o benchmark && ./benchmark

// Should use make to compile the program more humanly. 