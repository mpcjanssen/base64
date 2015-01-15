#ifndef _BASE64_H
#define _BASE64_H

#include <stddef.h>	/* size_t */

struct base64_state {
	int eof;
	int bytes;
	unsigned char carry;
#ifdef WITH_URLSAFE
        int urlsafe;
#endif
        const char *base64_table_enc;
        const char *base64_table_enc_T; /* transposed table */
};

/* Wrapper function to encode a plain string of given length. Output is written
 * to *out without trailing zero. Output length in bytes is written to *outlen.
 * The buffer in `out` has been allocated by the caller and is at least 4/3 the
 * size of the input: */
extern void base64_encode (const char *const src, size_t srclen, char *const out, size_t *const outlen
#ifdef WITH_URLSAFE
                    ,int urlsafe
#endif
                    );

/* Call this before calling base64_stream_encode() to init the state: */
extern void base64_stream_encode_init (struct base64_state *
#ifdef WITH_URLSAFE
                                , int urlsafe
#endif
                                );

/* Encodes the block of data of given length at `src`, into the buffer at
 * `out`. Caller is responsible for allocating a large enough out-buffer; it
 * must be at least 4/3 the size of the in-buffer, but take some margin. Places
 * the number of new bytes written into `outlen` (which is set to zero when the
 * function starts). Does not zero-terminate or finalize the output. */
extern void base64_stream_encode_std (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);

/* Finalizes the output begun by previous calls to `base64_stream_encode()`.
 * Adds the required end-of-stream markers if appropriate. `outlen` is modified
 * and will contain the number of new bytes written at `out` (which will quite
 * often be zero). */
extern void base64_stream_encode_final (struct base64_state *, char *const out, size_t *outlen);

/* Wrapper function to decode a plain string of given length. Output is written
 * to *out without trailing zero. Output length in bytes is written to *outlen.
 * The buffer in `out` has been allocated by the caller and is at least 3/4 the
 * size of the input. */
extern int base64_decode (const char *const src, size_t srclen, char *const out, size_t *const outlen);

/* Call this before calling base64_stream_decode() to init the state: */
extern void base64_stream_decode_init (struct base64_state *);

/* Decodes the block of data of given length at `src`, into the buffer at
 * `out`. Caller is responsible for allocating a large enough out-buffer; it
 * must be at least 3/4 the size of the in-buffer, but take some margin. Places
 * the number of new bytes written into `outlen` (which is set to zero when the
 * function starts). Does not zero-terminate the output. Returns 1 if all is
 * well, and 0 if a decoding error was found, such as an invalid character. */
extern int base64_stream_decode_std (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);

/*
 * Accelerated versions
 *
 * These will be stubs when the relevant features aren't available at compile time.
 */
extern void base64_stream_encode_ssse3 (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern int base64_stream_decode_ssse3 (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern void base64_stream_encode_avx2 (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern int base64_stream_decode_avx2 (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern void base64_stream_encode_neon (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern int base64_stream_decode_neon (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern void base64_stream_encode_neon64 (struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);

/*
 * Function pointers to optimal codecs for the host CPU
 */
extern void (*base64_stream_encode)(struct base64_state *, const char *const src, size_t srclen, char *const out, size_t *const outlen);
extern int (*base64_stream_decode)(struct base64_state *state, const char *const src, size_t srclen, char *const out, size_t *const outlen);

/*
 * Codec selection
 */
#define BASE64_CODEC_STANDARD 1
#define BASE64_CODEC_SSSE3 2
#define BASE64_CODEC_AVX2 3
#define BASE64_CODEC_NEON 4
#define BASE64_CODEC_NEON64 5
extern int base64_choose_codec(void);

/*
 * Setup
 */
extern void query_cpu_features(void);
extern void _create_transposed_tables(void);

extern unsigned int have_ssse3;
extern unsigned int have_avx2;
extern unsigned int have_neon;
extern unsigned int have_neon64;

extern const unsigned char base64_table_dec[];

#endif /* _BASE64_H */
