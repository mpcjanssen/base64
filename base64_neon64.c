/*
 * ARM NEON-accelerated base64 codec (arm64 version).
 *
 * Note there is no separate decoder for ARM64 because there would be no performance difference.
 */
#include "base64.h"

#if defined(__ARM_NEON) && defined(__LP64__)
#include <arm_neon.h>

void
base64_stream_encode_neon64 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	/* Assume that *out is large enough to contain the output.
	 * Theoretically it should be 4/3 the length of src. */
	const unsigned char *c = (unsigned char *)src;
	char *o = out;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;

        /*
         * Store the entire encoding table into 4 128-bit vectors; we
         * copy from a transposed version of the table to match what
         * vld4q_u8 expects.
         */
        uint8x16x4_t venc4 = vld4q_u8((const unsigned char *) state->base64_table_enc_T);

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
                        /* ARM64 NEON version */
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

                                /* ARM64 allows lookup in a 64 byte table -- perfect! */
                                str = vqtbl4q_u8(venc4, res); /* look up each byte in the table */

                                /* store resulting 16 bytes in o */
                                vst1q_u8((void *) o, str);
				c += 12;	/* 3 * 4 bytes of input  */
				o += 16;	/* 4 * 4 bytes of output */
				outl += 16;
				srclen -= 12;
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

#else /* defined(__ARM_NEON) && defined(__LP64__) */
void
base64_stream_encode_neon64 (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
    (void) state;
    (void) src;
    (void) srclen;
    (void) out;
    (void) outlen;
}
#endif /* defined(__ARM_NEON) && defined(__LP64__) */
