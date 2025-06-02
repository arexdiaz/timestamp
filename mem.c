#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h> 


typedef unsigned __int64 u64;

static void serialize_cpu() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
}


static u64 measure_one_read(volatile char* addr) {
    serialize_cpu();
    _mm_mfence();

    _mm_clflush((void*)addr);
    _mm_mfence();

    serialize_cpu();
    u64 t1 = __rdtsc();

    char temp_val = *addr;
    (void)temp_val;

    serialize_cpu();
    u64 t2 = __rdtsc();

    _mm_mfence();
    serialize_cpu();

    return t2 - t1;
}

int main() {
    printf("Starting SLAT-like timing test...\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;

    void* mem = VirtualAlloc(NULL, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        perror("VirtualAlloc failed");
        return 1;
    }

    if (!VirtualLock(mem, pageSize)) {
        perror("VirtualLock failed");
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    volatile char* buf = (volatile char*)mem;

    *buf = (char)0xAB;

    const int SAMPLE_COUNT_SLAT = 10000;
    u64 samples_slat[SAMPLE_COUNT_SLAT];

    printf("Running %d samples...\n", SAMPLE_COUNT_SLAT);
    for (int i = 0; i < SAMPLE_COUNT_SLAT; ++i) {
        samples_slat[i] = measure_one_read(buf);
        if ((i + 1) % 1000 == 0) {
            printf("Completed %d samples...\n", i + 1);
        }
    }

    u64 sum = 0;
    for (int i = 0; i < SAMPLE_COUNT_SLAT; ++i) {
        sum += samples_slat[i];
    }

    u64 avg = (sum + (u64)SAMPLE_COUNT_SLAT / 2) / (u64)SAMPLE_COUNT_SLAT;

    printf("----------------------------------------\n");
    printf("Average read latency: %llu cycles\n", avg);
    printf("Target average to pass: < 2200 cycles\n");
    printf("----------------------------------------\n");

    if (avg > 2200) {
        printf("Result: Test FAILED (average is > 2200 cycles)\n");
    } else {
        printf("Result: Test PASSED (average is <= 2200 cycles)\n");
    }

    VirtualUnlock(mem, pageSize);
    VirtualFree(mem, 0, MEM_RELEASE);

    return 0;
}
