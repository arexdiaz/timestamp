// File: rdtsc_vmaware_test.cpp
// Implements RDTSC-based timing anomaly checks in C++.

#define _CRT_SECURE_NO_WARNINGS // For MSVC compatibility with some C standard functions

#include <windows.h>
#include <intrin.h>  // For __rdtsc, _mm_mfence, _mm_clflush, __cpuid, __rdtscp
#include <iostream>  // For std::cout, std::cerr, std::endl
#include <vector>    // For std::vector
#include <numeric>   // For std::accumulate
#include <iomanip>   // For std::hex, std::setw, std::setfill
#include <cstdint>   // For uint64_t

// For CallNtPowerInformation and PROCESSOR_POWER_INFORMATION
#include <powrprof.h>
#pragma comment(lib, "Powrprof.lib") // Link with Powrprof.lib for CallNtPowerInformation

// Define u64 for convenience (unsigned 64-bit integer)
// using u64 = unsigned __int64; // MSVC specific
using u64 = uint64_t; // C++11 standard

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
    _mm_clflush(const_cast<void*>(reinterpret_cast<const void*>(addr)));
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
#if defined(_MSC_VER) && defined(_M_X64)
    // For Windows x64 with MSVC, try executing __rdtscp directly
    // __try and __except are MSVC-specific Structured Exception Handling
    __try {
        __rdtscp(&rdtscp_aux);
        haveRdtscp = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // QueryPerformanceCounter might fail if an invalid instruction exception occurs
        haveRdtscp = false;
    }
#else
    // For other platforms/compilers (like MSVC x86) or if __try/__except is not desired, use CPUID.
    // Note: <intrin.h> provides __cpuid for MSVC. Other compilers might need different headers/methods.
    int regs[4] = {0};
    __cpuid(regs, 0x80000001); // Query extended features
    if ((regs[3] & (1U << 27))) { // Check EDX bit 27 for RDTSCP support
        haveRdtscp = true;
    } else {
        haveRdtscp = false;
    }
#endif

    if (!haveRdtscp) {
        std::cout << "TIMER: RDTSCP instruction not supported. (Anomaly Detected)" << std::endl;
        return true; // Anomaly detected as per original logic
    }
    std::cout << "TIMER: RDTSCP instruction is supported." << std::endl;

    // 2. SLAT-like check (Memory Read Latency Measurement)
    std::cout << "Starting SLAT-like timing test..." << std::endl;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;

    // Using LPVOID as VirtualAlloc returns it.
    LPVOID mem = VirtualAlloc(NULL, pageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        DWORD error = GetLastError();
        std::cerr << "VirtualAlloc failed. Error code: " << error << std::endl;
        // Original C++ code returns false (no anomaly) if allocation fails,
        // as the test itself cannot proceed.
        return false;
    }

    if (!VirtualLock(mem, pageSize)) {
        DWORD error = GetLastError();
        std::cerr << "VirtualLock failed. Error code: " << error << std::endl;
        VirtualFree(mem, 0, MEM_RELEASE);
        return false;
    }

    volatile char* buf = static_cast<volatile char*>(mem);
    *buf = static_cast<char>(0xAB); // Touch the page to ensure it's backed by physical RAM

    const int SAMPLE_COUNT_SLAT = 10000;
    std::vector<u64> samples_slat(SAMPLE_COUNT_SLAT);

    std::cout << "Running " << SAMPLE_COUNT_SLAT << " samples for SLAT check..." << std::endl;
    u64 sum_of_samples = 0;
    for (int i = 0; i < SAMPLE_COUNT_SLAT; ++i) {
        samples_slat[i] = measure_one_read(buf);
        sum_of_samples += samples_slat[i];
    }

    u64 average_latency = 0;
    if (SAMPLE_COUNT_SLAT > 0) {
        // Calculate average with rounding
        average_latency = (sum_of_samples + static_cast<u64>(SAMPLE_COUNT_SLAT) / 2) / static_cast<u64>(SAMPLE_COUNT_SLAT);
    }

    const u64 SLAT_LATENCY_THRESHOLD_CYCLES = 2200;
    std::cout << "TIMER: SLAT check - Measured average read latency: " << average_latency << " cycles." << std::endl;
    std::cout << "TIMER: SLAT check - Expected threshold: " << SLAT_LATENCY_THRESHOLD_CYCLES << " cycles." << std::endl;


    VirtualUnlock(mem, pageSize);
    VirtualFree(mem, 0, MEM_RELEASE); // Ensure MEM_RELEASE is used with size 0 for reserved/committed pages

    if (average_latency > SLAT_LATENCY_THRESHOLD_CYCLES) {
        std::cout << "TIMER: SLAT check - High latency detected. Average: " << average_latency
                  << " cycles (Threshold: " << SLAT_LATENCY_THRESHOLD_CYCLES << " cycles). (Anomaly Detected)" << std::endl;
        return true; // Anomaly detected
    }
    std::cout << "TIMER: SLAT check - Latency is within acceptable limits." << std::endl;

    // 3. Processor Power Information Check (Detects abnormally low CPU frequency)
    std::cout << "Checking processor frequency..." << std::endl;
    SYSTEM_INFO sysInfoPower;
    GetSystemInfo(&sysInfoPower);
    DWORD procCount = sysInfoPower.dwNumberOfProcessors;

    std::vector<PROCESSOR_POWER_INFORMATION> ppi(procCount);

    NTSTATUS status = CallNtPowerInformation(
        ProcessorInformation, // Information level
        NULL,                 // No input buffer
        0,                    // Input buffer size is 0
        ppi.data(),           // Output buffer
        sizeof(PROCESSOR_POWER_INFORMATION) * procCount // Output buffer size
    );

    if (status != ERROR_SUCCESS) { // ERROR_SUCCESS is 0 (defined in winerror.h)
        std::cerr << "CallNtPowerInformation failed with status: " << status
                  << " (0x" << std::hex << std::setw(8) << std::setfill('0') << status << std::dec << ")" << std::endl;
        return false; // Cannot perform test
    }

    bool lowFreqDetected = false;
    for (DWORD i = 0; i < procCount; ++i) {
        std::cout << "  Core " << ppi[i].Number << ": CurrentMhz: " << ppi[i].CurrentMhz
                  << ", MaxMhz: " << ppi[i].MaxMhz << std::endl;
        if (ppi[i].CurrentMhz < 1000) { // Threshold of 1000 MHz
            std::cout << "TIMER: Low current CPU frequency detected on core " << ppi[i].Number
                      << ": " << ppi[i].CurrentMhz << " MHz. (Anomaly Detected)" << std::endl;
            lowFreqDetected = true;
            // break; // Exit loop early if one core is enough to trigger (optional)
        }
    }

    if (lowFreqDetected) {
        return true; // Anomaly detected
    }
    std::cout << "TIMER: Processor frequencies appear normal." << std::endl;

    return false; // No anomalies detected by these checks
}

int main() {
    std::cout << "Starting VM-aware RDTSC timing tests..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    bool anomaly_detected = check_timing_anomalies();

    std::cout << "----------------------------------------" << std::endl;
    if (anomaly_detected) {
        std::cout << "Overall Result: Potential VM or timing anomaly DETECTED." << std::endl;
    } else {
        std::cout << "Overall Result: No specific timing anomalies detected by this test." << std::endl;
    }
    std::cout << "----------------------------------------" << std::endl;

    // Optional: Pause to see output when run directly from an IDE or by double-clicking
    // std::cout << "Press Enter to exit..." << std::endl;
    // std::cin.get();

    return 0;
}
