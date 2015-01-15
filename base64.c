#include <string.h>     /* memcpy */
#include <stdio.h>

#include "base64.h"

/*#define VERBOSE*/

/*
 * Function pointers to chosen codec functions for this CPU.
 */
static int base64_codec_chosen = 0;
void (*base64_stream_encode)(struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen) = NULL;
int (*base64_stream_decode)(struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen) = NULL;

static const char base64_table_enc[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_table_enc_urlsafe[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Transposed versions of the tables above, for ARM64 NEON, generated at runtime */
static char base64_table_enc_T[65];
static char base64_table_enc_urlsafe_T[65];
void
_create_transposed_tables()
{
    static unsigned int transposed = 0;

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

int
base64_choose_codec()
{
    if (!base64_codec_chosen) {
        base64_stream_encode = base64_stream_encode_std;
        base64_stream_decode = base64_stream_decode_std;
        base64_codec_chosen = BASE64_CODEC_STANDARD;

        /* query the CPU for available features */
        query_cpu_features();

        if (have_avx2) {
            base64_stream_encode = base64_stream_encode_avx2;
            base64_stream_decode = base64_stream_decode_avx2;
            base64_codec_chosen = BASE64_CODEC_AVX2;
#ifdef VERBOSE
            printf("libbase64: using AVX2 instructions\n");
#endif
        }
        else if (have_ssse3) {
            base64_stream_encode = base64_stream_encode_ssse3;
            base64_stream_decode = base64_stream_decode_ssse3;
            base64_codec_chosen = BASE64_CODEC_SSSE3;
#ifdef VERBOSE
            printf("libbase64: using SSSE3 instructions\n");
#endif
        }
#ifndef __ARM_ARCH_7A__ /* NEON is slower on ARMv7a */
        else if (have_neon) {
            if (have_neon64) {
                base64_stream_encode = base64_stream_encode_neon64;
                base64_codec_chosen = BASE64_CODEC_NEON64;

                /* ARM64 NEON needs transposed tables */
                _create_transposed_tables();

#ifdef VERBOSE
                printf("libbase64: using NEON64 instructions\n");
#endif
            }
            else {
                base64_stream_encode = base64_stream_encode_neon;
                base64_codec_chosen = BASE64_CODEC_NEON;
#ifdef VERBOSE
                printf("libbase64: using NEON instructions\n");
#endif
            }

            /* both ARM variants use the same decoder */
            base64_stream_decode = base64_stream_decode_neon;
        }
#endif /* __ARM_ARCH_7A__ */
    }
    return base64_codec_chosen;
}

/* In the lookup table below, note that the value for '=' (character 61) is
 * 254, not 255. This character is used for in-band signaling of the end of
 * the datastream, and we will use that later. The characters A-Z, a-z, 0-9
 * and + / are mapped to their "decoded" values. The other bytes all map to
 * the value 255, which flags them as "invalid input". */
const unsigned char base64_table_dec[] = {
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
        base64_choose_codec();

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
        base64_choose_codec();
	state->eof = 0;
	state->bytes = 0;
	state->carry = 0;
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
	(*base64_stream_encode)(&state, src, srclen, out, &s);

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
	return (*base64_stream_decode)(&state, src, srclen, out, outlen);
}
