#include <stddef.h>	/* size_t */

/*
 * x86 acceleration
 *
 * We detect features using cpuid, but we still need compiler support
 * for extended instructions.
 */
#if __x86_64__ || __i386__
#if defined(__SSSE3__) || defined(__AVX2__)
#include <immintrin.h>
#endif
#include <cpuid.h>
#endif

/*
 * ARM acceleration
 *
 * __ARM_NEON indicates ARMv7+, which has NEON instructions
 * __LP64__ indicates ARMv8+, which has a few extensions to the original NEON
 */
/*#undef __ARM_NEON*/
#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

#include "base64.h"

static const char base64_table_enc[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_table_enc_urlsafe[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Transposed versions of the tables above, for ARM NEON, generated at runtime */
static char base64_table_enc_T[65];
static char base64_table_enc_urlsafe_T[65];


#if __x86_64__ || __i386__
/*
 * Intel instrinsic functions we use.
 * See: https://software.intel.com/sites/landingpage/IntrinsicsGuide for details.
 *
 * [SSE]
 *   Intrinsic             CPUID    Operation
 *   _mm_add_epi8          SSE2     Add packed 8-bit integers in a and b, and store the results in dst.
 *   _mm_andnot_si128      SSE2     dst[127:0] := ((NOT a[127:0]) AND b[127:0])
 *   _mm_cmpeq_epi8        SSE2     Compare packed 8-bit integers in a and b for equality, and store the results in dst.
 *   _mm_cmplt_epi8        SSE2     Compare packed 8-bit integers in a and b for less-than, and store the results in dst.
 *   _mm_loadu_si128       SSE2     Load 128-bits of integer data from memory into dst
 *   _mm_movemask_epi8     SSE2     Create mask from the most significant bit of each 8-bit element in a, and store the result in dst.
 *   _mm_set1_epi32        SSE2     Broadcast 32-bit integer a to all elements of dst.
 *   _mm_set1_epi8         SSE2     Broadcast 8-bit integer a to all elements of dst. This intrinsic may generate vpbroadcastb.
 *   _mm_setr_epi8         SSE2     Set packed 8-bit integers in dst with the supplied values in reverse order.
 *   _mm_shuffle_epi8      SSSE3    Shuffle packed 8-bit integers in a according to shuffle control mask in the corresponding 8-bit element of b, and store the results in dst.
 *   _mm_li_epi32          SSE2     Shift packed 32-bit integers in a left by imm while shifting in zeros, and store the results in dst.
 *   _mm_srli_epi32        SSE2     Shift packed 32-bit integers in a right by imm while shifting in zeros, and store the results in dst.
 *   _mm_storeu_si128      SSE2     Store 128-bits of integer data from a into memory. mem_addr does not need to be aligned on any particular boundary.
 *   _mm_sub_epi8          SSE2     Subtract packed 8-bit integers in b from packed 8-bit integers in a, and store the results in dst.
 *
 * [AVX]
 *  _mm256_loadu_si256     AVX      Load 256-bits of integer data from memory into dst. mem_addr does not need to be aligned on any particular boundary.
 *  _mm256_set1_epi32      AVX      Broadcast 32-bit integer a to all elements of dst.
 *  _mm256_set1_epi8       AVX      Broadcast 8-bit integer a to all elements of dst.
 *  _mm256_setr_epi8       AVX      Set packed 8-bit integers in dst with the supplied values in reverse order.
 *  _mm256_storeu_si256    AVX      Store 256-bits of integer data from a into memory. mem_addr does not need to be aligned on any particular boundary.
 *
 * [AVX2]
 *
 *  _mm256_add_epi8        AVX2     Add packed 8-bit integers in a and b, and store the results in dst.
 *  _mm256_andnot_si256    AVX2     dst[255:0] := ((NOT a[255:0]) AND b[255:0])
 *  _mm256_cmpeq_epi8      AVX2     Compare packed 8-bit integers in a and b for equality, and store the results in dst.
 *  _mm256_cmplt_epi8      AVX2     Compare packed 8-bit integers in a and b for less-than, and store the results in dst.
 *  _mm256_movemask_epi256 AVX2     Create mask from the most significant bit of each 8-bit element in a, and store the result in dst.
 *  _mm256_slli_epi32      AVX2     Shift packed 32-bit integers in a left by imm while shifting in zeros, and store the results in dst.
 *  _mm256_srli_epi32      AVX2     Shift packed 32-bit integers in a right by imm while shifting in zeros, and store the results in dst.
 *  _mm256_sub_epi8        AVX2     Subtract packed 8-bit integers in b from packed 8-bit integers in a, and store the results in dst.
 */
static unsigned int have_features = 0;
static unsigned int have_ssse3 = 0;
static unsigned int have_avx2 = 0;
static unsigned int _cpuid_eax_1 = 0;
static unsigned int _cpuid_ebx_1 = 0;
static unsigned int _cpuid_ecx_1 = 0;
static unsigned int _cpuid_edx_1 = 0;
static unsigned int _cpuid_eax_7 = 0;
static unsigned int _cpuid_ebx_7 = 0;
static unsigned int _cpuid_ecx_7 = 0;
static unsigned int _cpuid_edx_7 = 0;

/* use CPUID to get x86 processor features */
static void inline
_init_x86_features()
{
    if (!have_features) {
        __get_cpuid(/*level:*/ 1, &_cpuid_eax_1, &_cpuid_ebx_1, &_cpuid_ecx_1, &_cpuid_edx_1);
        have_features = 1;
        have_ssse3 = _cpuid_ecx_1 & bit_SSE3;

        __get_cpuid(/*level:*/ 7, &_cpuid_eax_7, &_cpuid_ebx_7, &_cpuid_ecx_7, &_cpuid_edx_7);
        have_avx2 = _cpuid_ebx_7 & (1 << 5);

        have_avx2 = 1;

        printf("have_ssse3 = %d\n", have_ssse3);
        printf("have_avx2 = %d\n", have_avx2);

#ifdef __AVX2__
        printf("compiled with AVX2 support...\n");
#else
        printf("compiled without AVX2 support...\n");
#endif
    }
}
#endif

/* only certain instructions sets require transposed tables */
#define NEED_TRANSPOSED_TABLES __ARM_NEON

#ifdef NEED_TRANSPOSED_TABLES
static unsigned int transposed = 0;
static void inline
_create_transposed_tables()
{
    const char *E;
    const char *p0, *p1, *p2, *p3;
    char enc[64];
    int i;

    if (!transposed) {
        /* transpose the encoding tables to match what vld4q_u8 expects */
        for (E = (const char *) base64_table_enc, i = 0, p0 = &E[0], p1 = &E[16], p2 = &E[32], p3 = &E[48]; i < 16; i++) {
            enc[i*4  ] = p0[i];
            enc[i*4+1] = p1[i];
            enc[i*4+2] = p2[i];
            enc[i*4+3] = p3[i];
        }
        memcpy(base64_table_enc_T, enc, 64);

        /* transpose URL-safe table */
        for (E = (const char *) base64_table_enc_urlsafe, i = 0, p0 = &E[0], p1 = &E[16], p2 = &E[32], p3 = &E[48]; i < 16; i++) {
            enc[i*4  ] = p0[i];
            enc[i*4+1] = p1[i];
            enc[i*4+2] = p2[i];
            enc[i*4+3] = p3[i];
        }
        memcpy(base64_table_enc_urlsafe_T, enc, 64);

        transposed = 1;
    }
}
#endif

/* In the lookup table below, note that the value for '=' (character 61) is
 * 254, not 255. This character is used for in-band signaling of the end of
 * the datastream, and we will use that later. The characters A-Z, a-z, 0-9
 * and + / are mapped to their "decoded" values. The other bytes all map to
 * the value 255, which flags them as "invalid input". */
static const unsigned char
base64_table_dec[] =
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,		/*   0..15 */
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,		/*  16..31 */
#ifdef WITH_URLSAFE
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255,  62, 255,  63,		/*  32..47 */
#else
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,		/*  32..47 */
#endif
	 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 254, 255, 255,		/*  48..63 */
	255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,		/*  64..79 */
#ifdef WITH_URLSAFE
	 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,		/*  80..95 */
#else
	 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,		/*  80..95 */
#endif
	255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,		/*  96..111 */
	 41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,		/* 112..127 */
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,		/* 128..143 */
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
};

void
base64_stream_encode_init (struct base64_state *state
#ifdef WITH_URLSAFE
                           , int urlsafe
#endif
                           )
{
#ifdef NEED_TRANSPOSED_TABLES
        _create_transposed_tables();
#endif

	state->eof = 0;
	state->bytes = 0;
	state->carry = 0;
#ifdef WITH_URLSAFE
        state->urlsafe = urlsafe ? 1 : 0;
        state->base64_table_enc = urlsafe ? base64_table_enc_urlsafe : base64_table_enc;
        state->base64_table_enc_T = urlsafe ? base64_table_enc_urlsafe_T : base64_table_enc_T;
#else
        state->base64_table_enc = base64_table_enc;
        state->base64_table_enc_T = base64_table_enc_T;
#endif
}

void
base64_stream_encode (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	/* Assume that *out is large enough to contain the output.
	 * Theoretically it should be 4/3 the length of src. */
	const unsigned char *c = (unsigned char *)src;
	char *o = out;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;

#ifdef __ARM_NEON
#ifdef __LP64__
        /*
         * Store the entire encoding table into 4 128-bit vectors; we
         * copy from a transposed version of the table to match what
         * vld4q_u8 expects.
         */
        uint8x16x4_t venc4 = vld4q_u8(state->base64_table_enc_T);
#endif
#endif

#if __x86_64__ || __i386__
        _init_x86_features();
#endif


	st.bytes = state->bytes;
	st.carry = state->carry;

	/* Turn three bytes into four 6-bit numbers: */
	/* in[0] = 00111111 */
	/* in[1] = 00112222 */
	/* in[2] = 00222233 */
	/* in[3] = 00333333 */

	/* Duff's device, a for() loop inside a switch() statement. Legal! */
	switch (st.bytes)
	{
		for (;;)
		{
		case 0:
#ifdef __AVX2__ /* x86_64 arch build only */
                if (have_avx2) {
			/* If we have AVX2 support, pick off 24 bytes at a
			 * time for as long as we can: */
                        while (srclen >= 28) /* read 28 bytes, process the first 24, and output 32 */
			{
                                __m128i l0, l1;
				__m256i str, mask, res, blockmask;
				__m256i s1, s2, s3, s4, s5;
				__m256i s1mask, s2mask, s3mask, s4mask;

                                /* _mm256_shuffle_epi8 works on 128-bit lanes, so we need to get the two 128-bit
                                 * lanes into big-endian order separately. */
                                l0 = _mm_loadu_si128((__m128i *) c);
				l0 = _mm_shuffle_epi8(l0,
     			             _mm_setr_epi8(2, 2, 1, 0, 5, 5, 4, 3, 8, 8, 7, 6, 11, 11, 10, 9));

                                l1 = _mm_loadu_si128((__m128i *) &c[12]);
				l1 = _mm_shuffle_epi8(l1,
     			             _mm_setr_epi8(2, 2, 1, 0, 5, 5, 4, 3, 8, 8, 7, 6, 11, 11, 10, 9));

                                /* Now we can combine into a single 256-bit register */
                                str = _mm256_insertf128_si256(str, l0, 0);
                                str = _mm256_insertf128_si256(str, l1, 1);

				/* Mask to pass through only the lower 6 bits of one byte: */
				mask = _mm256_set1_epi32(0x3F000000);

				/* Shift bits by 2, mask in only the first byte: */
				res = _mm256_srli_epi32(str, 2) & mask;
				mask = _mm256_srli_epi32(mask, 8);

				/* Shift bits by 4, mask in only the second byte: */
				res |= _mm256_srli_epi32(str, 4) & mask;
				mask = _mm256_srli_epi32(mask, 8);

				/* Shift bits by 6, mask in only the third byte: */
				res |= _mm256_srli_epi32(str, 6) & mask;
				mask = _mm256_srli_epi32(mask, 8);

				/* No shift necessary for the fourth byte because we duplicated
				 * the third byte to this position; just mask: */
				res |= str & mask;

				/* Reorder to 32-bit little-endian: */
				res = _mm256_shuffle_epi8(res,
				      _mm256_setr_epi8(3, 2, 1, 0,
                                                       7, 6, 5, 4,
                                                       11, 10, 9, 8,
                                                       15, 14, 13, 12,
                                                       19, 18, 17, 16,
                                                       23, 22, 21, 20,
                                                       27, 26, 25, 24,
                                                       31, 30, 29, 28));

				/* The bits have now been shifted to the right locations;
				 * translate their values 0..63 to the Base64 alphabet: */

                                /* set 1: 63, '/' */
                                s1mask = _mm256_cmpgt_epi8(res, _mm256_set1_epi8(62));
                                blockmask = s1mask;

                                /* set 2: 62, '+' */
                                s2mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(res, _mm256_set1_epi8(61)));
                                blockmask |= s2mask;

				/* set 3: 52..61, "0123456789" */
                                s3mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(res, _mm256_set1_epi8(51)));
                                blockmask |= s3mask;

				/* set 4: 26..51, "abcdefghijklmnopqrstuvwxyz" */
                                s4mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(res, _mm256_set1_epi8(25)));
                                blockmask |= s4mask;

				/* set 1: 0..25, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				 * Everything that is not blockmasked */

				/* Create the masked character sets: */
#ifdef WITH_URLSAFE
				s1 = s1mask & _mm256_set1_epi8(state->urlsafe ? '_' :'/');
#else
                                s1 = s1mask & _mm256_set1_epi8('/');
#endif
#ifdef WITH_URLSAFE
				s2 = s2mask & _mm256_set1_epi8(state->urlsafe ? '-' : '+');
#else
				s2 = s2mask & _mm256_set1_epi8('+');
#endif
				s3 = s3mask & _mm256_add_epi8(res, _mm256_set1_epi8('0' - 52));
				s4 = s4mask & _mm256_add_epi8(res, _mm256_set1_epi8('a' - 26));
				s5 = _mm256_andnot_si256(blockmask, _mm256_add_epi8(res, _mm256_set1_epi8('A')));

				/* Blend all the sets together and store: */
				_mm256_storeu_si256((__m256i *) o, s1 | s2 | s3 | s4 | s5);

				c += 24;	/* 6 * 4 bytes of input  */
				o += 32;	/* 8 * 4 bytes of output */
				outl += 32;
				srclen -= 24;
			}
                }
#endif /* __AVX2__ */
#ifdef __SSSE3__ /* x86_64 arch build only */
                if (have_ssse3) {
			/* If we have SSSE3 support, pick off 12 bytes at a
			 * time for as long as we can: */
                        while (srclen >= 16) /* read 16 bytes, process the first 12, and output 16 */
			{
				__m128i str, mask, res, blockmask;
				__m128i s1, s2, s3, s4, s5;
				__m128i s1mask, s2mask, s3mask, s4mask;

				/* Load string: */
				str = _mm_loadu_si128((__m128i *)c);

				/* Reorder to 32-bit big-endian, duplicating the third byte in every block of four.
				 * This copies the third byte to its final destination, so we can include it later
				 * by just masking instead of shifting and masking.
				 * The workset must be in big-endian, otherwise the shifted bits do not carry over
				 * properly among adjacent bytes: */
				str = _mm_shuffle_epi8(str,
				      _mm_setr_epi8(2, 2, 1, 0, 5, 5, 4, 3, 8, 8, 7, 6, 11, 11, 10, 9));

				/* Mask to pass through only the lower 6 bits of one byte: */
				mask = _mm_set1_epi32(0x3F000000);

				/* Shift bits by 2, mask in only the first byte: */
				res = _mm_srli_epi32(str, 2) & mask;
				mask = _mm_srli_epi32(mask, 8);

				/* Shift bits by 4, mask in only the second byte: */
				res |= _mm_srli_epi32(str, 4) & mask;
				mask = _mm_srli_epi32(mask, 8);

				/* Shift bits by 6, mask in only the third byte: */
				res |= _mm_srli_epi32(str, 6) & mask;
				mask = _mm_srli_epi32(mask, 8);

				/* No shift necessary for the fourth byte because we duplicated
				 * the third byte to this position; just mask: */
				res |= str & mask;

				/* Reorder to 32-bit little-endian: */
				res = _mm_shuffle_epi8(res,
				      _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));

				/* The bits have now been shifted to the right locations;
				 * translate their values 0..63 to the Base64 alphabet: */

				/* set 1: 0..25, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
				s1mask = _mm_cmplt_epi8(res, _mm_set1_epi8(26));
				blockmask = s1mask;

				/* set 2: 26..51, "abcdefghijklmnopqrstuvwxyz" */
				s2mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(res, _mm_set1_epi8(52)));
				blockmask |= s2mask;

				/* set 3: 52..61, "0123456789" */
				s3mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(res, _mm_set1_epi8(62)));
				blockmask |= s3mask;

				/* set 4: 62, "+" */
				s4mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(res, _mm_set1_epi8(63)));
				blockmask |= s4mask;

				/* set 5: 63, "/"
				 * Everything that is not blockmasked */

				/* Create the masked character sets: */
				s1 = s1mask & _mm_add_epi8(res, _mm_set1_epi8('A'));
				s2 = s2mask & _mm_add_epi8(res, _mm_set1_epi8('a' - 26));
				s3 = s3mask & _mm_add_epi8(res, _mm_set1_epi8('0' - 52));
#ifdef WITH_URLSAFE
				s4 = s4mask & _mm_set1_epi8(state->urlsafe ? '-' : '+');
#else
				s4 = s4mask & _mm_set1_epi8('+');
#endif
#ifdef WITH_URLSAFE
				s5 = _mm_andnot_si128(blockmask, _mm_set1_epi8(state->urlsafe ? '_' : '/'));
#else
				s5 = _mm_andnot_si128(blockmask, _mm_set1_epi8('/'));
#endif

				/* Blend all the sets together and store: */
				_mm_storeu_si128((__m128i *)o, s1 | s2 | s3 | s4 | s5);

				c += 12;	/* 3 * 4 bytes of input  */
				o += 16;	/* 4 * 4 bytes of output */
				outl += 16;
				srclen -= 12;
			}
                }
#endif
#if defined(__ARM_NEON)
                        /* ARM NEON version */
                        while (srclen >= 16) /* we read 16 bytes, process the first 12, and output 16 */
			{
                                uint8x16_t str, mask, res;

				/* Load string: */
                                str = vld1q_u8((void *) c);

				/* Reorder to 32-bit big-endian, duplicating the third byte in every block of four.
				 * This copies the third byte to its final destination, so we can include it later
				 * by just masking instead of shifting and masking.
				 * The workset must be in big-endian, otherwise the shifted bits do not carry over
				 * properly among adjacent bytes: */
                                str = __builtin_shufflevector(str,
                                                              str,
                                                              2, 2, 1, 0,
                                                              5, 5, 4, 3,
                                                              8, 8, 7, 6,
                                                              11, 11, 10, 9);

				/* Mask to pass through only the lower 6 bits of one byte: */
                                mask = vdupq_n_u32(0x3F000000);

				/* Shift bits by 2, mask in only the first byte: */
                                res = vshrq_n_u32(str, 2) & mask;
                                mask = vshrq_n_u32(mask, 8);

				/* Shift bits by 4, mask in only the second byte: */
                                res |= vshrq_n_u32(str, 4) & mask;
                                mask = vshrq_n_u32(mask, 8);

				/* Shift bits by 6, mask in only the third byte: */
                                res |= vshrq_n_u32(str, 6) & mask;
                                mask = vshrq_n_u32(mask, 8);

				/* No shift necessary for the fourth byte because we duplicated
				 * the third byte to this position; just mask: */
				res |= str & mask;

				/* Reorder to 32-bit little-endian: */
                                res = __builtin_shufflevector(res,
                                                              res,
                                                              3, 2, 1, 0,
                                                              7, 6, 5, 4,
                                                              11, 10, 9, 8,
                                                              15, 14, 13, 12);


#ifdef __LP64__
                                /* ARM64 allows lookup in a 64 byte table -- perfect! */
                                str = vqtbl4q_u8(venc4, res); /* look up each byte in the table */

                                /* store resulting 16 bytes in o */
                                vst1q_u8((void *) o, str);
#else /* __LP64__ */
                                /*
                                 * ARMv7 allows lookup only in a 32 byte table, so we need to
                                 * do this in two parts
                                 */
#endif /* __LP64__ */
				c += 12;	/* 3 * 4 bytes of input  */
				o += 16;	/* 4 * 4 bytes of output */
				outl += 16;
				srclen -= 12;
			}
#endif /* __ARM_NEON */

			if (srclen-- == 0) {
				break;
			}
			*o++ = state->base64_table_enc[*c >> 2];
			st.carry = (*c++ << 4) & 0x30;
			st.bytes++;
			outl += 1;

		case 1:	if (srclen-- == 0) {
				break;
			}
			*o++ = state->base64_table_enc[st.carry | (*c >> 4)];
			st.carry = (*c++ << 2) & 0x3C;
			st.bytes++;
			outl += 1;

		case 2:	if (srclen-- == 0) {
				break;
			}
			*o++ = state->base64_table_enc[st.carry | (*c >> 6)];
			*o++ = state->base64_table_enc[*c++ & 0x3F];
			st.bytes = 0;
			outl += 2;
		}
	}
	state->bytes = st.bytes;
	state->carry = st.carry;
	*outlen = outl;
}

void
base64_stream_encode_final (struct base64_state *state, char *const out, size_t *const outlen)
{
	char *o = out;

	if (state->bytes == 1) {
		*o++ = state->base64_table_enc[state->carry];
		*o++ = '=';
		*o++ = '=';
		*outlen = 3;
		return;
	}
	if (state->bytes == 2) {
		*o++ = state->base64_table_enc[state->carry];
		*o++ = '=';
		*outlen = 2;
		return;
	}
	*outlen = 0;
}

void
base64_stream_decode_init (struct base64_state *state)
{
	state->eof = 0;
	state->bytes = 0;
	state->carry = 0;
}

int
base64_stream_decode (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	int ret = 0;
	const char *c = src;
	char *o = out;
	unsigned char q;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;

#if __x86_64__ || __i386__
        _init_x86_features();
#endif

	st.eof = state->eof;
	st.bytes = state->bytes;
	st.carry = state->carry;

	/* If we previously saw an EOF or an invalid character, bail out: */
	if (st.eof) {
		*outlen = 0;
		return 0;
	}
	/* Turn four 6-bit numbers into three bytes: */
	/* out[0] = 11111122 */
	/* out[1] = 22223333 */
	/* out[2] = 33444444 */

	/* Duff's device again: */
	switch (st.bytes)
	{
		for (;;)
		{
		case 0:
#ifdef SKIP_INVALID
                label0:;
#endif

#ifdef __AVX2__ /* x86_64 arch build only */
                if (have_avx2) {
			/* If we have AVX2 support, pick off 32 bytes at a time for as long
			 * as we can, but make sure that we quit before seeing any == markers
			 * at the end of the string. Also, because we write 8 zeroes at
			 * the end of the output, ensure that there are at least 12 valid bytes
			 * of input data remaining to close the gap. 32 + 2 + 12 = 46 bytes: */
			while (srclen >= 46)
			{
				__m256i str, mask, res;
				__m256i s1mask, s2mask, s3mask, s4mask, s5mask;

				/* Load string: */
				str = _mm256_loadu_si256((__m256i *)c);

				/* Classify characters into five sets:
				 * Set 1: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
				s1mask = _mm256_andnot_si256(
                                                _mm256_cmpgt_epi8(str, _mm256_set1_epi8('Z')),
						_mm256_cmpgt_epi8(str, _mm256_set1_epi8('A' - 1)));

				/* Set 2: "abcdefghijklmnopqrstuvwxyz" */
				s2mask = _mm256_andnot_si256(
                                                _mm256_cmpgt_epi8(str, _mm256_set1_epi8('z')),
						_mm256_cmpgt_epi8(str, _mm256_set1_epi8('a' - 1)));

				/* Set 3: "0123456789" */
				s3mask = _mm256_andnot_si256(
                                                _mm256_cmpgt_epi8(str, _mm256_set1_epi8('9')),
						_mm256_cmpgt_epi8(str, _mm256_set1_epi8('0' - 1)));

				/* Set 4: "+" */
#ifdef WITH_URLSAFE
				s4mask = _mm256_or_si256(
                                                _mm256_cmpeq_epi8(str, _mm256_set1_epi8('-')),
                                                _mm256_cmpeq_epi8(str, _mm256_set1_epi8('+')));
#else
				s4mask = _mm256_cmpeq_epi8(str, _mm256_set1_epi8('+'));
#endif
				/* Set 5: "/" */
#ifdef WITH_URLSAFE
				s5mask = _mm256_or_si256(
                                                _mm256_cmpeq_epi8(str, _mm256_set1_epi8('_')),
                                                _mm256_cmpeq_epi8(str, _mm256_set1_epi8('/')));
#else
				s5mask = _mm256_cmpeq_epi8(str, _mm256_set1_epi8('/'));
#endif

				/* Check if all bytes have been classified; else fall back on bytewise code
				 * to do error checking and reporting: */
				if (_mm256_movemask_epi8(s1mask | s2mask | s3mask | s4mask | s5mask) != 0xFFFF)
					break;

				/* Subtract sets from byte values: */
				res  = s1mask & _mm256_sub_epi8(str, _mm256_set1_epi8('A'));
				res |= s2mask & _mm256_sub_epi8(str, _mm256_set1_epi8('a' - 26));
				res |= s3mask & _mm256_sub_epi8(str, _mm256_set1_epi8('0' - 52));
				res |= s4mask & _mm256_set1_epi8(62);
				res |= s5mask & _mm256_set1_epi8(63);

				/* Shuffle bytes to 32-bit bigendian: */
				res = _mm256_shuffle_epi8(res,
				      _mm256_setr_epi8(3, 2, 1, 0,
                                                       7, 6, 5, 4,
                                                       11, 10, 9, 8,
                                                       15, 14, 13, 12,
                                                       19, 18, 17, 16,
                                                       23, 22, 21, 20,
                                                       27, 26, 25, 24,
                                                       31, 30, 29, 28));

				/* Mask in a single byte per shift: */
				mask = _mm256_set1_epi32(0x3F000000);

				/* Pack bytes together: */
				str = _mm256_slli_epi32(res & mask, 2);
				mask = _mm256_srli_epi32(mask, 8);

				str |= _mm256_slli_epi32(res & mask, 4);
				mask = _mm256_srli_epi32(mask, 8);

				str |= _mm256_slli_epi32(res & mask, 6);
				mask = _mm256_srli_epi32(mask, 8);

				str |= _mm256_slli_epi32(res & mask, 8);

				/* Reshuffle and repack into 12-byte output format: */
				str = _mm256_shuffle_epi8(str,
				      _mm256_setr_epi8(3, 2, 1,
                                                       7, 6, 5,
                                                       11, 10, 9,
                                                       15, 14, 13,
                                                       19, 18, 17,
                                                       23, 22, 21,
                                                       27, 26, 25,
                                                       31, 30, 29,
                                                       -1, -1, -1,
                                                       -1, -1, -1,
                                                       -1,
                                                       -1));

				/* Store back: */
				_mm256_storeu_si256((__m256i *)o, str);

				c += 32;
				o += 24;
				outl += 24;
				srclen -= 32;
			}
                }
#endif /* __AVX2__ */
#ifdef __SSSE3__ /* x86_64 arch build only */
                if (have_ssse3) {
			/* If we have SSSE3 support, pick off 16 bytes at a time for as long
			 * as we can, but make sure that we quit before seeing any == markers
			 * at the end of the string. Also, because we write four zeroes at
			 * the end of the output, ensure that there are at least 6 valid bytes
			 * of input data remaining to close the gap. 16 + 2 + 6 = 24 bytes: */
			while (srclen >= 24)
			{
				__m128i str, mask, res;
				__m128i s1mask, s2mask, s3mask, s4mask, s5mask;

				/* Load string: */
				str = _mm_loadu_si128((__m128i *)c);

				/* Classify characters into five sets:
				 * Set 1: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
				s1mask = _mm_andnot_si128(
						_mm_cmplt_epi8(str, _mm_set1_epi8('A')),
						_mm_cmplt_epi8(str, _mm_set1_epi8('Z' + 1)));

				/* Set 2: "abcdefghijklmnopqrstuvwxyz" */
				s2mask = _mm_andnot_si128(
						_mm_cmplt_epi8(str, _mm_set1_epi8('a')),
						_mm_cmplt_epi8(str, _mm_set1_epi8('z' + 1)));

				/* Set 3: "0123456789" */
				s3mask = _mm_andnot_si128(
						_mm_cmplt_epi8(str, _mm_set1_epi8('0')),
						_mm_cmplt_epi8(str, _mm_set1_epi8('9' + 1)));

				/* Set 4: "+" */
#ifdef WITH_URLSAFE
				s4mask = _mm_or_si128(
                                                _mm_cmpeq_epi8(str, _mm_set1_epi8('-')),
                                                _mm_cmpeq_epi8(str, _mm_set1_epi8('+')));
#else
				s4mask = _mm_cmpeq_epi8(str, _mm_set1_epi8('+'));
#endif
				/* Set 5: "/" */
#ifdef WITH_URLSAFE
				s5mask = _mm_or_si128(
                                                _mm_cmpeq_epi8(str, _mm_set1_epi8('_')),
                                                _mm_cmpeq_epi8(str, _mm_set1_epi8('/')));
#else
				s5mask = _mm_cmpeq_epi8(str, _mm_set1_epi8('/'));
#endif
				/* Check if all bytes have been classified; else fall back on bytewise code
				 * to do error checking and reporting: */
				if (_mm_movemask_epi8(s1mask | s2mask | s3mask | s4mask | s5mask) != 0xFFFF)
                                        break;

				/* Subtract sets from byte values: */
				res  = s1mask & _mm_sub_epi8(str, _mm_set1_epi8('A'));
				res |= s2mask & _mm_sub_epi8(str, _mm_set1_epi8('a' - 26));
				res |= s3mask & _mm_sub_epi8(str, _mm_set1_epi8('0' - 52));
				res |= s4mask & _mm_set1_epi8(62);
				res |= s5mask & _mm_set1_epi8(63);
				/* Shuffle bytes to 32-bit bigendian: */
				res = _mm_shuffle_epi8(res,
				      _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));

				/* Mask in a single byte per shift: */
				mask = _mm_set1_epi32(0x3F000000);

				/* Pack bytes together: */
				str = _mm_slli_epi32(res & mask, 2);
				mask = _mm_srli_epi32(mask, 8);
				str |= _mm_slli_epi32(res & mask, 4);
				mask = _mm_srli_epi32(mask, 8);
				str |= _mm_slli_epi32(res & mask, 6);
				mask = _mm_srli_epi32(mask, 8);
				str |= _mm_slli_epi32(res & mask, 8);

				/* Reshuffle and repack into 12-byte output format: */
				str = _mm_shuffle_epi8(str,
				      _mm_setr_epi8(3, 2, 1, 7, 6, 5, 11, 10, 9, 15, 14, 13, -1, -1, -1, -1));

				/* Store back: */
				_mm_storeu_si128((__m128i *)o, str);

				c += 16;
				o += 12;
				outl += 12;
				srclen -= 16;
			}
                }
#endif /* __SSSE3__ */
#ifdef __ARM_NEON
                        /*
                         * ARM NEON allows us to process 16 bytes and output 12.
                         * This is similar to the approach taken with SSSE3.
                         */
			while (srclen >= 24)
			{
				uint8x16_t str, mask, res;
				uint8x16_t s1mask, s2mask, s3mask, s4mask, s5mask;

				/* Load string: */
                                str = vld1q_u8((void *) c);

				/* Classify characters into five sets:
				 * Set 1: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
				s1mask = vcgeq_u8(str, vdupq_n_u8('A')) & /* >= A */
                                         vcleq_u8(str, vdupq_n_u8('Z')) ; /* <= Z */

				/* Set 2: "abcdefghijklmnopqrstuvwxyz" */
				s2mask = vcgeq_u8(str, vdupq_n_u8('a')) & /* >= a */
                                         vcleq_u8(str, vdupq_n_u8('z')) ; /* <= z */

				/* Set 3: "0123456789" */
				s3mask = vcgeq_u8(str, vdupq_n_u8('0')) & /* >= 0 */
                                         vcleq_u8(str, vdupq_n_u8('9')) ; /* <= 9 */

				/* Set 4: "+" */
#ifdef WITH_URLSAFE
                                s4mask = vceqq_u8(str, vdupq_n_u8('-')) |
                                         vceqq_u8(str, vdupq_n_u8('+')) ;
#else
                                s4mask = vceqq_u8(str, vdupq_n_u8('+'));
#endif
				/* Set 5: "/" */
#ifdef WITH_URLSAFE
                                s5mask = vceqq_u8(str, vdupq_n_u8('_')) |
                                         vceqq_u8(str, vdupq_n_u8('/')) ;
#else
                                s5mask = vceqq_u8(str, vdupq_n_u8('/'));
#endif
				/* Check if all bytes have been classified; else fall back on bytewise code
				 * to do error checking and reporting: */
                                uint64x2_t bits = vreinterpretq_u64_u32(s1mask | s2mask | s3mask | s4mask | s5mask);
                                uint64_t b0 = vgetq_lane_u64(bits, 0);
                                uint64_t b1 = vgetq_lane_u64(bits, 1);
                                if (b0 != 0xFFFFFFFFFFFFFFFF || b1 != 0xFFFFFFFFFFFFFFFF)
                                    break;

				/* Subtract sets from byte values: */
                                res  = s1mask & vsubq_u8(str, vdupq_n_u8('A'));
                                res |= s2mask & vsubq_u8(str, vdupq_n_u8('a' - 26));
                                res |= s3mask & vsubq_u8(str, vdupq_n_u8('0' - 52));
				res |= s4mask & vdupq_n_u8(62);
                                res |= s5mask & vdupq_n_u8(63);

				/* Shuffle bytes to 32-bit bigendian: */
                                res = __builtin_shufflevector(res,
                                                              res,
                                                              3, 2, 1, 0,
                                                              7, 6, 5, 4,
                                                              11, 10, 9, 8,
                                                              15, 14, 13, 12);

				/* Mask in a single byte per shift: */
				mask = vdupq_n_u32(0x3F000000);

				/* Pack bytes together: */
                                str  = vshlq_n_u32(res & mask, 2);
                                mask = vshrq_n_u32(mask, 8);
                                str |= vshlq_n_u32(res & mask, 4);
                                mask = vshrq_n_u32(mask, 8);
                                str |= vshlq_n_u32(res & mask, 6);
                                mask = vshrq_n_u32(mask, 8);
                                str |= vshlq_n_u32(res & mask, 8);

				/* Reshuffle and repack into 12-byte output format: */
                                str = __builtin_shufflevector(str,
                                                              str,
                                                              3, 2, 1,
                                                              7, 6, 5,
                                                              11, 10, 9,
                                                              15, 14, 13,
                                                              -1, -1, -1, -1);

                                /* store resulting 16 bytes in o */
                                vst1q_u8((void *) o, str);

				c += 16;
				o += 12;
				outl += 12;
				srclen -= 16;
                        }
#endif /* __ARM_NEON */

			if (srclen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[(unsigned char)*c++]) >= 254) {
#ifdef SKIP_INVALID
                                goto label0;
#endif
				st.eof = 1;
				/* Treat character '=' as invalid for byte 0: */
				break;
			}
			st.carry = q << 2;
			st.bytes++;
		case 1:
#ifdef SKIP_INVALID
                label1:;
#endif
                        if (srclen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[(unsigned char)*c++]) >= 254) {
#ifdef SKIP_INVALID
                                goto label1;
#endif
				st.eof = 1;
				/* Treat character '=' as invalid for byte 1: */
				break;
			}
			*o++ = st.carry | (q >> 4);
			st.carry = q << 4;
			st.bytes++;
			outl++;

		case 2:
#ifdef SKIP_INVALID
                label2:;
#endif
                        if (srclen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[(unsigned char)*c++]) >= 254) {
#ifdef SKIP_INVALID
                                goto label2;
#endif
				st.eof = 1;
				/* When q == 254, the input char is '='. Return 1 and EOF.
				 * Technically, should check if next byte is also '=', but never mind.
				 * When q == 255, the input char is invalid. Return 0 and EOF. */
				ret = (q == 254) ? 1 : 0;
				break;
			}
			*o++ = st.carry | (q >> 2);
			st.carry = q << 6;
			st.bytes++;
			outl++;

		case 3:
#ifdef SKIP_INVALID
                label3:;
#endif
                        if (srclen-- == 0) {
				ret = 1;
				break;
			}
			if ((q = base64_table_dec[(unsigned char)*c++]) >= 254) {
#ifdef SKIP_INVALID
                                goto label3;
#endif
				st.eof = 1;
				/* When q == 254, the input char is '='. Return 1 and EOF.
				 * When q == 255, the input char is invalid. Return 0 and EOF. */
				ret = (q == 254) ? 1 : 0;
				break;
			}
			*o++ = st.carry | q;
			st.carry = 0;
			st.bytes = 0;
			outl++;
		}
	}
	state->eof = st.eof;
	state->bytes = st.bytes;
	state->carry = st.carry;
	*outlen = outl;
	return ret;
}

void
base64_encode (const char *const src, size_t srclen, char *const out, size_t *const outlen
#ifdef WITH_URLSAFE
               , int urlsafe
#endif
               )
{
	size_t s;
	size_t t;
	struct base64_state state;

	/* Init the stream reader: */
#ifdef WITH_URLSAFE
	base64_stream_encode_init(&state, urlsafe);
#else
	base64_stream_encode_init(&state);
#endif

	/* Feed the whole string to the stream reader: */
	base64_stream_encode(&state, src, srclen, out, &s);

	/* Finalize the stream by writing trailer if any: */
	base64_stream_encode_final(&state, out + s, &t);

	/* Final output length is stream length plus tail: */
	*outlen = s + t;
}

int
base64_decode (const char *const src, size_t srclen, char *const out, size_t *outlen)
{
	struct base64_state state;

	base64_stream_decode_init(&state);
	return base64_stream_decode(&state, src, srclen, out, outlen);
}
