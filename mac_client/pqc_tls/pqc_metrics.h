/**
 * @file pqc_metrics.h
 * @brief PQC TLS Metrics Collection Utilities
 */

#ifndef PQC_METRICS_H
#define PQC_METRICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CPU 사이클 카운터 읽기 (x86_64)
 */
static inline uint64_t pqc_get_cpu_cycles(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    return 0; // Not supported
#endif
}

#ifdef __cplusplus
}
#endif

#endif // PQC_METRICS_H


