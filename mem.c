// File: rdtsc_vmaware_test.c
// Implements RDTSC-based timing anomaly checks inspired by the provided C++ example.

#define _CRT_SECURE_NO_WARNINGS // For MSVC compatibility with some C standard functions

#include <windows.h>
#include <intrin.h>  // For __rdtsc, _mm_mfence, _mm_clflush, __cpuid, __rdtscp
#include <stdio.h>   // For printf, perror
#include <stdbool.h> // For bool type
#include <stdlib.h>  // For malloc, free

// For CallNtPowerInformation and PROCESSOR_POWER_INFORMATION
#include <powrprof.h>
#pragma comment(lib, "Powrprof.lib") // Link with PowrProf.lib for CallNtPowerInformation

// Define u64 for convenience (unsigned 64-bit integer)
typedef unsigned __int64 u64;

// CPU serialization function using CPUID
static void serialize_cpu() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0); // CPUID is a serializing instruction
}

// Measures the time taken for a single cache-flushed memory read
static u64 measure_one_read(volatile char* addr) {
    serialize_cpu();
    _mm_mfence(); // Memory fence to ensure prior instructions complete

    // Flush the cache line for the given address
    _mm_clflush((void*)addr); // _mm_clflush expects void const*
    _mm_mfence(); // Memory fence to ensure flush completes before timing

    serialize_cpu();
    u64 t1 = __rdtsc(); // Read Time Stamp Counter

    // The actual memory read we are timing
    volatile char value_read = *addr;
    (void)value_read; // Use the value to prevent optimization and suppress unused variable warning

    serialize_cpu(); // Ensure the read is complete before the second timestamp
    u64 t2 = __rdtsc(); // Read Time Stamp Counter again

    _mm_mfence(); // Full memory barrier to ensure all operations complete
    serialize_cpu();

    return t2 - t1; // Return the difference in cycles
}

// Main function to check for timing anomalies.
// Returns true if an anomaly is detected, false otherwise.
static bool check_timing_anomalies() {
    unsigned int rdtscp_aux = 0; // Variable for __rdtscp output
    bool haveRdtscp = false;

    // 1. Check for __rdtscp support (RDTSCP is a serializing variant of RDTSC)
    // The original C++ code uses this check: if !haveRdtscp, it's considered an anomaly.
#if defined(_WIN32) && defined(_M_X64) && defined(_MSC_VER)
    // For Windows x64 with MSVC, try executing __rdtscp directly
    __try {
        __rdtscp(&rdtscp_aux);
        haveRdtscp = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        haveRdtscp = false;
    }
#else
    // For other platforms/compilers or Windows x86, use CPUID
    (void)rdtscp_aux; // Mark as unused in this path
    int regs[4] = {0};
    __cpuid(regs, 0x80000001); // Query extended features
    if ((regs[3] & (1U << 27))) { // Check EDX bit 27 for RDTSCP support
        haveRdtscp = true;
    } else {
        haveRdtscp = false;
    }
#endif

    if (!haveRdtscp) {
        printf("TIMER: RDTSCP instruction not supported. (Anomaly Detected)\n");
        return true; // Anomaly detected as per original logic
    }
    printf("TIMER: RDTSCP instruction is supported.\n");

    // 2. SLAT-like check (Memory Read Latency Measurement)
    printf("Starting SLAT-like timing test...\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;

    void* mem = VirtualAlloc(NULL, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        perror("VirtualAlloc failed");
        // Original C++ code returns false (no anomaly) if allocation fails,
        // as the test itself cannot proceed.
        return false;
    }

    if (!VirtualLock(mem, pageSize)) {
        perror("VirtualLock failed");
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }

    volatile char* buf = (volatile char*)mem;
    *buf = (char)0xAB; // Touch the page to ensure it's backed by physical RAM

    const int SAMPLE_COUNT_SLAT = 10000;
    u64* samples_slat = (u64*)malloc(SAMPLE_COUNT_SLAT * sizeof(u64));
    if (!samples_slat) {
        printf("Failed to allocate memory for samples.\n");
        VirtualUnlock(mem, pageSize);
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }

    printf("Running %d samples for SLAT check...\n", SAMPLE_COUNT_SLAT);
    u64 sum_of_samples = 0;
    for (int i = 0; i < SAMPLE_COUNT_SLAT; ++i) {
        samples_slat[i] = measure_one_read(buf);
        sum_of_samples += samples_slat[i];
    }
    free(samples_slat);

    u64 average_latency = 0;
    if (SAMPLE_COUNT_SLAT > 0) {
        // Calculate average with rounding
        average_latency = (sum_of_samples + (u64)SAMPLE_COUNT_SLAT / 2) / (u64)SAMPLE_COUNT_SLAT;
    }

    printf("TIMER: SLAT check - Measured average read latency: %llu cycles.\n", average_latency);

    VirtualUnlock(mem, pageSize);
    VirtualFree(mem, 0, MEM_RELEASE);

    const u64 SLAT_LATENCY_THRESHOLD_CYCLES = 2200;
    if (average_latency > SLAT_LATENCY_THRESHOLD_CYCLES) {
        printf("TIMER: SLAT check - High latency detected. Average: %llu cycles (Threshold: %llu cycles). (Anomaly Detected)\n",
               average_latency, SLAT_LATENCY_THRESHOLD_CYCLES);
        return true; // Anomaly detected
    }
    printf("TIMER: SLAT check - Latency is within acceptable limits.\n");

    // 3. Processor Power Information Check (Detects abnormally low CPU frequency)
    printf("Checking processor frequency...\n");
    SYSTEM_INFO sysInfoPower; // Use a new SYSTEM_INFO struct or reuse 'si'
    GetSystemInfo(&sysInfoPower);
    DWORD procCount = sysInfoPower.dwNumberOfProcessors;

    PROCESSOR_POWER_INFORMATION* ppi =
        (PROCESSOR_POWER_INFORMATION*)malloc(sizeof(PROCESSOR_POWER_INFORMATION) * procCount);
    if (!ppi) {
        printf("Failed to allocate memory for processor power information.\n");
        return false; // Cannot perform test
    }

    // CallNtPowerInformation is defined in powrprof.h (via powerbase.h)
    // ProcessorInformation is an enum member of POWER_INFORMATION_LEVEL.
    NTSTATUS status = CallNtPowerInformation(
        ProcessorInformation, // Information level
        NULL,                 // No input buffer
        0,                    // Input buffer size is 0
        ppi,                  // Output buffer
        sizeof(PROCESSOR_POWER_INFORMATION) * procCount // Output buffer size
    );

    if (status != ERROR_SUCCESS) { // ERROR_SUCCESS is 0, same as STATUS_SUCCESS for this context
        printf("CallNtPowerInformation failed with status: %ld (0x%08lx)\n", status, status);
        free(ppi);
        return false; // Cannot perform test
    }

    bool lowFreqDetected = false;
    for (DWORD i = 0; i < procCount; ++i) {
        printf("  Core %lu: CurrentMhz: %lu, MaxMhz: %lu\n",
               ppi[i].Number, ppi[i].CurrentMhz, ppi[i].MaxMhz);
        if (ppi[i].CurrentMhz < 1000) {
            printf("TIMER: Low current CPU frequency detected on core %lu: %lu MHz. (Anomaly Detected)\n",
                   ppi[i].Number, ppi[i].CurrentMhz);
            lowFreqDetected = true;
            // Original C++ code returns true immediately upon detection.
            // break; // Exit loop early if one core is enough to trigger
        }
    }
    free(ppi);

    if (lowFreqDetected) {
        return true; // Anomaly detected
    }
    printf("TIMER: Processor frequencies appear normal.\n");

    return false; // No anomalies detected by these checks
}

int main() {
    printf("Starting VM-aware RDTSC timing tests...\n");
    printf("----------------------------------------\n");

    bool anomaly_detected = check_timing_anomalies();

    printf("----------------------------------------\n");
    if (anomaly_detected) {
        printf("Overall Result: Potential VM or timing anomaly DETECTED.\n");
    } else {
        printf("Overall Result: No specific timing anomalies detected by this test.\n");
    }
    printf("----------------------------------------\n");

    // Optional: Pause to see output when run directly
    // printf("Press Enter to exit...\n");
    // getchar();

    return 0;
}

