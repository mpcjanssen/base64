/*
 * ARM NEON-accelerated base64 codec (armv7 version).
 */
#include "base64.h"

#ifdef __ARM_NEON
#include <arm_neon.h>

void
base64_stream_encode_neon (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
	/* Assume that *out is large enough to contain the output.
	 * Theoretically it should be 4/3 the length of src. */
	const unsigned char *c = (unsigned char *)src;
	char *o = out;

	/* Use local temporaries to avoid cache thrashing: */
	size_t outl = 0;
	struct base64_state st;
#ifdef WITH_URLSAFE
        uint8x16_t dash_or_plus = vmovq_n_u8(state->urlsafe ? '-' : '+');
#else
        uint8x16_t dash_or_plus = vmovq_n_u8('+');
#endif
#ifdef WITH_URLSAFE
        uint8x16_t underscore_or_forward_slash = vmovq_n_u8(state->urlsafe ? '_' : '/');
#else
        uint8x16_t underscore_or_forward_slash = vmovq_n_u8('/');
#endif
        uint8x16_t sixty_two = vmovq_n_u8(62);

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
                        /* ARM NEON version */
                        while (srclen >= 16) /* we read 16 bytes, process the first 12, and output 16 */
			{
                                uint8x16_t str, mask, res;
				uint8x16_t s1, s2, s3, s4, s5;
				uint8x16_t s1mask, s2mask, s3mask, s4mask;
				uint8x16_t blockmask;

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

				/* The bits have now been shifted to the right locations;
				 * translate their values 0..63 to the Base64 alphabet: */

				/* set 1: 0..25, "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
                                s1mask = vcltq_u8(res, vmovq_n_u8(26));
				blockmask = s1mask;

				/* set 2: 26..51, "abcdefghijklmnopqrstuvwxyz" */
                                s2mask = vandq_u8(vmvnq_u8(blockmask), vcltq_u8(res, vmovq_n_u8(52)));
				blockmask |= s2mask;

				/* set 3: 52..61, "0123456789" */
                                s3mask = vandq_u8(vmvnq_u8(blockmask), vcltq_u8(res, sixty_two));
				blockmask |= s3mask;

				/* set 4: 62, "+" */
                                s4mask = vceqq_u8(res, sixty_two);
				blockmask |= s4mask;

				/* set 5: 63, "/"
				 * Everything that is not blockmasked */

				/* Create the masked character sets: */
                                s1 = vandq_u8(s1mask, vaddq_u8(res, vmovq_n_u8('A'))); /* 65 */
                                s2 = vandq_u8(s2mask, vaddq_u8(res, vmovq_n_u8('a' - 26))); /* 71 */
                                s3 = vandq_u8(s3mask, vaddq_u8(res, vmovq_n_u8('0' - 52))); /* -4 */
                                s4 = vandq_u8(s4mask, dash_or_plus);
                                s5 = vandq_u8(vmvnq_u8(blockmask), underscore_or_forward_slash);

				/* Blend all the sets together and store: */
                                vst1q_u8((void *) o, s1|s2|s3|s4|s5);

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
int
base64_stream_decode_neon (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
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
			/* If we have NEON support, pick off 16 bytes at a time for as long
			 * as we can, but make sure that we quit before seeing any == markers
			 * at the end of the string. Also, because we write four zeroes at
			 * the end of the output, ensure that there are at least 6 valid bytes
			 * of input data remaining to close the gap. 16 + 2 + 6 = 24 bytes: */
			while (srclen >= 24)
			{
				uint8x16_t str, mask, res;
				uint8x16_t s1mask, s2mask, s3mask, s4mask, s5mask;

				/* Load string: */
                                str = vld1q_u8((void *) c);

				/* Classify characters into five sets:
				 * Set 1: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
				s1mask = vandq_u8(vcgeq_u8(str, vdupq_n_u8('A')),  /* >= A */
                                                  vcleq_u8(str, vdupq_n_u8('Z'))); /* <= Z */

				/* Set 2: "abcdefghijklmnopqrstuvwxyz" */
				s2mask = vandq_u8(vcgeq_u8(str, vdupq_n_u8('a')),  /* >= a */
                                                  vcleq_u8(str, vdupq_n_u8('z'))); /* <= z */

				/* Set 3: "0123456789" */
				s3mask = vandq_u8(vcgeq_u8(str, vdupq_n_u8('0')),  /* >= 0 */
                                                  vcleq_u8(str, vdupq_n_u8('9'))); /* <= 9 */

				/* Set 4: "+" */
#ifdef WITH_URLSAFE
                                s4mask = vorrq_u8(vceqq_u8(str, vdupq_n_u8('-')),
                                                  vceqq_u8(str, vdupq_n_u8('+')));
#else
                                s4mask = vceqq_u8(str, vdupq_n_u8('+'));
#endif
				/* Set 5: "/" */
#ifdef WITH_URLSAFE
                                s5mask = vorrq_u8(vceqq_u8(str, vdupq_n_u8('_')),
                                                  vceqq_u8(str, vdupq_n_u8('/')));
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
#else /* __ARM_NEON */
void
base64_stream_encode_neon (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
    (void) state;
    (void) src;
    (void) srclen;
    (void) out;
    (void) outlen;
}
int
base64_stream_decode_neon (struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen)
{
    (void) state;
    (void) src;
    (void) srclen;
    (void) out;
    (void) outlen;
    return 0;
}
#endif /* __ARM_NEON */
