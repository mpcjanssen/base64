/*
 * CPU feature detection
 */
#include <stdio.h>
#include "base64.h"

static unsigned int have_features = 0;

unsigned int have_ssse3 = 0;
unsigned int have_avx2 = 0;
unsigned int have_neon = 0;
unsigned int have_neon64 = 0;

#if __x86_64__ || __i386__
#include <cpuid.h>

static unsigned int _cpuid_eax_1 = 0;
static unsigned int _cpuid_ebx_1 = 0;
static unsigned int _cpuid_ecx_1 = 0;
static unsigned int _cpuid_edx_1 = 0;
static unsigned int _cpuid_eax_7 = 0;
static unsigned int _cpuid_ebx_7 = 0;
static unsigned int _cpuid_ecx_7 = 0;
static unsigned int _cpuid_edx_7 = 0;

/* use CPUID to get x86 processor features */
void
query_cpu_features()
{
/* older cpuid.h doesn't have this bit defined: */
#ifndef bit_AVX2
#define bit_AVX2 (1 << 5)
#endif

    if (!have_features) {
        unsigned int max_level = __get_cpuid_max(0, NULL);

        if (max_level > 0) {
            __get_cpuid(/*level:*/ 1, &_cpuid_eax_1, &_cpuid_ebx_1, &_cpuid_ecx_1, &_cpuid_edx_1);
            have_features = 1;
            have_ssse3 = _cpuid_ecx_1 & bit_SSE3;
#if 1
            printf("1:eax = %08x\n", _cpuid_eax_1);
            printf("1:ebx = %08x\n", _cpuid_ebx_1);
            printf("1:ecx = %08x\n", _cpuid_ecx_1);
            printf("1:edx = %08x\n", _cpuid_edx_1);
#endif
            if (max_level >= 7) {
                unsigned int eax, ebx, ecx, edx;
                __cpuid_count(7, 0, eax, ebx, ecx, edx);
                have_avx2 = (ebx & bit_AVX2) ? 1 : 0;
                _cpuid_eax_7 = eax;
                _cpuid_ebx_7 = ebx;
                _cpuid_ecx_7 = ecx;
                _cpuid_edx_7 = edx;
            }
#if 1
            printf("7:eax = %08x\n", _cpuid_eax_7);
            printf("7:ebx = %08x\n", _cpuid_ebx_7);
            printf("7:ecx = %08x\n", _cpuid_ecx_7);
            printf("7:edx = %08x\n", _cpuid_edx_7);
#endif
        }
#if 1
        printf("have_ssse3 = %d\n", have_ssse3);
        printf("have_avx2 = %d\n", have_avx2);
#endif
    }
}
#elif __ARM_NEON
void
query_cpu_features()
{
    if (!have_features) {
        /* For ARM we just rely on compile-time settings */
#ifdef __ARM_NEON
        have_neon = 1;
#ifdef __LP64__
        have_neon64 = 1;
#endif
#endif
        have_features = 1;

        printf("have_neon = %d\n", have_neon);
        printf("have_neon64 = %d\n", have_neon64);
    }

}
#else
/* unknown target -- no features */
void
query_cpu_features()
{
    if (!have_features)
        have_features = 1;
}
#endif
