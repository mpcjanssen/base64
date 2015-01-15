/*
 * AVX2-accelerated base64 codec.
 */
#include "base64.h"

#ifdef __AVX2__
#include <immintrin.h>

void
base64_stream_encode_avx2 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	/* Assume that *out is large enough to contain the output.
	 * Theoretically it should be 4/3 the length of src. */
	const unsigned char *c = (unsigned char *)src;
	char *o = out;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;

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
#pragma GCC diagnostic ignored "-Wuninitialized"
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

int
base64_stream_decode_avx2 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	int ret = 0;
	const char *c = src;
	char *o = out;
	unsigned char q;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;

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
			/* If we have AVX2 support, pick off 32 bytes at a time for as long
			 * as we can, but make sure that we quit before seeing any == markers
			 * at the end of the string. Also, because we write 4 zeroes at
			 * the end of the output, ensure that there are at least 6 valid bytes
			 * of input data remaining to close the gap. 32 + 2 + 6 = 40 bytes: */
			while (srclen >= 40)
			{
                                __m128i l0, l1;
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
				if ((unsigned int ) _mm256_movemask_epi8(s1mask | s2mask | s3mask | s4mask | s5mask) != 0xFFFFFFFF)
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
                                                       3, 2, 1, 0,
                                                       7, 6, 5, 4,
                                                       11, 10, 9, 8,
                                                       15, 14, 13, 12));

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

                                /* As in AVX2 encoding, we have to shuffle and repack
                                 * each 128-bit lane separately due to the way
                                 * _mm256_shuffle_epi8 works */
				l0 = _mm_shuffle_epi8(
                                     _mm256_extractf128_si256(str, 0),
                                     _mm_setr_epi8(3, 2, 1,
                                                   7, 6, 5,
                                                   11, 10, 9,
                                                   15, 14, 13,
                                                   -1, -1, -1, -1));
				l1 = _mm_shuffle_epi8(
                                     _mm256_extractf128_si256(str, 1),
                                     _mm_setr_epi8(3, 2, 1,
                                                   7, 6, 5,
                                                   11, 10, 9,
                                                   15, 14, 13,
                                                   -1, -1, -1, -1));

				/* Store back: */
				_mm_storeu_si128((__m128i *)o, l0);
				_mm_storeu_si128((__m128i *)&o[12], l1);

				c += 32;
				o += 24;
				outl += 24;
				srclen -= 32;
			}
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
#else /* __AVX2__ */
void
base64_stream_encode_avx2 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
    (void) state;
    (void) src;
    (void) srclen;
    (void) out;
    (void) outlen;
}
int
base64_stream_decode_avx2 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
    (void) state;
    (void) src;
    (void) srclen;
    (void) out;
    (void) outlen;
    return 0;
}
#endif /*__AVX2__*/
