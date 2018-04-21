/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

/*
 * AVX and especially XOP speed up Salsa20 a lot, but this mostly matters for
 * classic scrypt and for YESCRYPT_WORM (which use 8 rounds of Salsa20 per
 * sub-block), and much less so for YESCRYPT_RW (which uses 2 rounds of Salsa20
 * per block except during pwxform S-box initialization).
 */
#ifdef __XOP__
#warning "Note: XOP is enabled, which is great for classic scrypt and YESCRYPT_WORM, but is usually slightly slower than plain SSE2 for YESCRYPT_RW"
#elif defined(__AVX__)
#warning "Note: AVX is enabled, which is great for classic scrypt and YESCRYPT_WORM, but is usually slightly slower than plain SSE2 for YESCRYPT_RW"
#else
#warning "Note: AVX and XOP are not enabled, which is great for YESCRYPT_RW, but they would substantially improve performance at classic scrypt and YESCRYPT_WORM"
#endif

/*
 * The SSE4 code version has fewer instructions than the generic SSE2 version,
 * but all of the instructions are SIMD, thereby wasting the scalar execution
 * units.  Thus, the generic SSE2 version below actually runs faster on some
 * CPUs due to its balanced mix of SIMD and scalar instructions.
 */
#undef USE_SSE4_FOR_32BIT

/*
 * GCC before 4.9 would by default unnecessarily use store/load (without
 * SSE4.1) or (V)PEXTR (with SSE4.1 or AVX) instead of simply (V)MOV.
 * This was tracked as GCC bug 54349.
 * "-mtune=corei7" works around this, but is only supported for GCC 4.6+.
 * We use inline asm for pre-4.6 GCC, further down this file.
 */
#if __GNUC__ == 4 && __GNUC_MINOR__ >= 6 && __GNUC_MINOR__ < 9 && \
    !defined(__clang__) && !defined(__ICC)
#pragma GCC target ("tune=corei7")
#endif

#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"

#define YESCRYPT_INTERNAL
#include "yescrypt.h"

#include "yescrypt-platform.c"

#if __STDC_VERSION__ >= 199901L
/* Have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

#ifdef __GNUC__
#define unlikely(exp) __builtin_expect(exp, 0)
#else
#define unlikely(exp) (exp)
#endif

#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));

#ifdef __XOP__
#define ARX(out, in1, in2, s) \
	out = _mm_xor_si128(out, _mm_roti_epi32(_mm_add_epi32(in1, in2), s));
#else
#define ARX(out, in1, in2, s) { \
	__m128i T = _mm_add_epi32(in1, in2); \
	out = _mm_xor_si128(out, _mm_slli_epi32(T, s)); \
	out = _mm_xor_si128(out, _mm_srli_epi32(T, 32-s)); \
}
#endif

#define SALSA20_2ROUNDS(X0, X1, X2, X3) \
	/* Operate on "columns" */ \
	ARX(X1, X0, X3, 7) \
	ARX(X2, X1, X0, 9) \
	ARX(X3, X2, X1, 13) \
	ARX(X0, X3, X2, 18) \
\
	/* Rearrange data */ \
	X1 = _mm_shuffle_epi32(X1, 0x93); \
	X2 = _mm_shuffle_epi32(X2, 0x4E); \
	X3 = _mm_shuffle_epi32(X3, 0x39); \
\
	/* Operate on "rows" */ \
	ARX(X3, X0, X1, 7) \
	ARX(X2, X3, X0, 9) \
	ARX(X1, X2, X3, 13) \
	ARX(X0, X1, X2, 18) \
\
	/* Rearrange data */ \
	X1 = _mm_shuffle_epi32(X1, 0x39); \
	X2 = _mm_shuffle_epi32(X2, 0x4E); \
	X3 = _mm_shuffle_epi32(X3, 0x93);

typedef union {
	uint32_t w[16];
	__m128i q[4];
} salsa20_blk_t;

#define DECL_X \
	__m128i X0, X1, X2, X3;

#define READ_X(in) \
	X0 = (in).q[0]; \
	X1 = (in).q[1]; \
	X2 = (in).q[2]; \
	X3 = (in).q[3];

#define SALSA20_BEGIN(maybe_decl) \
	maybe_decl Y0 = X0; \
	maybe_decl Y1 = X1; \
	maybe_decl Y2 = X2; \
	maybe_decl Y3 = X3;

#define SALSA20_END(out) \
	(out).q[0] = X0 = _mm_add_epi32(X0, Y0); \
	(out).q[1] = X1 = _mm_add_epi32(X1, Y1); \
	(out).q[2] = X2 = _mm_add_epi32(X2, Y2); \
	(out).q[3] = X3 = _mm_add_epi32(X3, Y3);

#define INTEGERIFY(x) \
	_mm_cvtsi128_si32(x)

/**
 * Apply the Salsa20/8 core to the block provided in (X0 ... X3) ^ (Z0 ... Z3).
 */
#define SALSA20_8_XOR_ANY(maybe_decl, Z0, Z1, Z2, Z3, out) \
	X0 = _mm_xor_si128(X0, Z0); \
	X1 = _mm_xor_si128(X1, Z1); \
	X2 = _mm_xor_si128(X2, Z2); \
	X3 = _mm_xor_si128(X3, Z3); \
	{ \
		SALSA20_BEGIN(maybe_decl) \
		SALSA20_2ROUNDS(X0, X1, X2, X3) \
		SALSA20_2ROUNDS(X0, X1, X2, X3) \
		SALSA20_2ROUNDS(X0, X1, X2, X3) \
		SALSA20_2ROUNDS(X0, X1, X2, X3) \
		SALSA20_END(out) \
	}

#define SALSA20_8_XOR_MEM(in, out) \
	SALSA20_8_XOR_ANY(__m128i, (in).q[0], (in).q[1], (in).q[2], (in).q[3], out)

#define SALSA20_8_XOR_REG(out) \
	SALSA20_8_XOR_ANY(/* empty */, Y0, Y1, Y2, Y3, out)

/**
 * blockmix_salsa8(Bin, Bout, r):
 * Compute Bout = BlockMix_{salsa20/8, r}(Bin).  The input Bin must be 128r
 * bytes in length; the output Bout must also be the same size.
 */
static void blockmix_salsa8(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r)
{
	size_t i;
	DECL_X

	READ_X(Bin[r * 2 - 1])
	for (i = 0; i < r; i++) {
		SALSA20_8_XOR_MEM(Bin[i * 2], Bout[i])
		SALSA20_8_XOR_MEM(Bin[i * 2 + 1], Bout[r + i])
	}
}

#define XOR4(in) \
	X0 = _mm_xor_si128(X0, (in).q[0]); \
	X1 = _mm_xor_si128(X1, (in).q[1]); \
	X2 = _mm_xor_si128(X2, (in).q[2]); \
	X3 = _mm_xor_si128(X3, (in).q[3]);

#define XOR4_2(in1, in2) \
	X0 = _mm_xor_si128((in1).q[0], (in2).q[0]); \
	X1 = _mm_xor_si128((in1).q[1], (in2).q[1]); \
	X2 = _mm_xor_si128((in1).q[2], (in2).q[2]); \
	X3 = _mm_xor_si128((in1).q[3], (in2).q[3]);

static uint32_t blockmix_salsa8_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    size_t r)
{
	size_t i;
	DECL_X

	r--;
	PREFETCH(&Bin2[r * 2 + 1], _MM_HINT_T0)
	for (i = 0; i < r; i++) {
		PREFETCH(&Bin2[i * 2], _MM_HINT_T0)
		PREFETCH(&Bin2[i * 2 + 1], _MM_HINT_T0)
	}
	PREFETCH(&Bin2[r * 2], _MM_HINT_T0)

	XOR4_2(Bin1[r * 2 + 1], Bin2[r * 2 + 1])
	for (i = 0; i <= r; i++) {
		XOR4(Bin1[i * 2])
		SALSA20_8_XOR_MEM(Bin2[i * 2], Bout[i])
		XOR4(Bin1[i * 2 + 1])
		SALSA20_8_XOR_MEM(Bin2[i * 2 + 1], Bout[r + 1 + i])
	}

	return INTEGERIFY(X0);
}

/**
 * Apply the Salsa20/2 core to the block provided in (X0 ... X3).
 */
#define SALSA20_2(out) { \
	SALSA20_BEGIN(__m128i) \
	SALSA20_2ROUNDS(X0, X1, X2, X3) \
	SALSA20_END(out) \
}

#define DECL_Y \
	__m128i Y0, Y1, Y2, Y3;

/*
 * (V)PSRLDQ and (V)PSHUFD have higher throughput than (V)PSRLQ on some CPUs
 * starting with Sandy Bridge.  Additionally, PSHUFD uses separate source and
 * destination registers, whereas the shifts would require an extra move
 * instruction for our code when building without AVX.  Unfortunately, PSHUFD
 * is much slower on Conroe (4 cycles latency vs. 1 cycle latency for PSRLQ)
 * and somewhat slower on some non-Intel CPUs (luckily not including AMD
 * Bulldozer and Piledriver).
 */
#ifdef __AVX__
#define HI32(X) \
	_mm_srli_si128((X), 4)
#elif 1 /* As an option, check for __SSE4_1__ here not to hurt Conroe */
#define HI32(X) \
	_mm_shuffle_epi32((X), _MM_SHUFFLE(2,3,0,1))
#else
#define HI32(X) \
	_mm_srli_epi64((X), 32)
#endif

#if defined(__x86_64__) && \
    __GNUC__ == 4 && __GNUC_MINOR__ < 6 && !defined(__ICC)
#ifdef __AVX__
#define MOVQ "vmovq"
#else
/* "movq" would be more correct, but "movd" is supported by older binutils
 * due to an error in AMD's spec for x86-64. */
#define MOVQ "movd"
#endif
#define EXTRACT64(X) ({ \
		uint64_t result; \
		__asm__(MOVQ " %1, %0" : "=r" (result) : "x" (X)); \
		result; \
	})
#elif defined(__x86_64__) && !defined(_MSC_VER) && !defined(__OPEN64__)
/* MSVC and Open64 had bugs */
#define EXTRACT64(X) _mm_cvtsi128_si64(X)
#elif defined(__x86_64__) && defined(__SSE4_1__)
/* No known bugs for this intrinsic */
#include <smmintrin.h>
#define EXTRACT64(X) _mm_extract_epi64((X), 0)
#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit */
#include <smmintrin.h>
#if 0
/* This is currently unused by the code below, which instead uses these two
 * intrinsics explicitly when (!defined(__x86_64__) && defined(__SSE4_1__)) */
#define EXTRACT64(X) \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
	((uint64_t)(uint32_t)_mm_extract_epi32((X), 1) << 32))
#endif
#else
/* 32-bit or compilers with known past bugs in _mm_cvtsi128_si64() */
#define EXTRACT64(X) \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(HI32(X)) << 32))
#endif

/* This is tunable */
#define Swidth 8

/* Not tunable in this implementation, hard-coded in a few places */
#define PWXsimple 2
#define PWXgather 4

/* Derived values.  Not tunable except via Swidth above. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define Sbytes (3 * (1 << Swidth) * PWXsimple * 8)
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define Smask2 (((uint64_t)Smask << 32) | Smask)

#define DECL_SMASK2REG /* empty */

#if defined(__x86_64__) && (defined(__AVX__) || !defined(__GNUC__))
/* 64-bit with AVX */
/* Force use of 64-bit AND instead of two 32-bit ANDs */
#undef DECL_SMASK2REG
#if defined(__GNUC__) && !defined(__ICC)
#define DECL_SMASK2REG uint64_t Smask2reg = Smask2;
/* Force use of lower-numbered registers to reduce number of prefixes, relying
 * on out-of-order execution and register renaming. */
#define FORCE_REGALLOC_1 \
	__asm__("" : "=a" (x), "+d" (Smask2reg), "+S" (S0), "+D" (S1));
#define FORCE_REGALLOC_2 \
	__asm__("" : : "c" (lo));
#else
static volatile uint64_t Smask2var = Smask2;
#define DECL_SMASK2REG uint64_t Smask2reg = Smask2var;
#define FORCE_REGALLOC_1 /* empty */
#define FORCE_REGALLOC_2 /* empty */
#endif
#define PWXFORM_SIMD(X) { \
	uint64_t x; \
	FORCE_REGALLOC_1 \
	uint32_t lo = x = EXTRACT64(X) & Smask2reg; \
	FORCE_REGALLOC_2 \
	uint32_t hi = x >> 32; \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, *(__m128i *)(S0 + lo)); \
	X = _mm_xor_si128(X, *(__m128i *)(S1 + hi)); \
}
#elif defined(__x86_64__)
/* 64-bit without AVX.  This relies on out-of-order execution and register
 * renaming.  It may actually be fastest on CPUs with AVX(2) as well - e.g.,
 * it runs great on Haswell. */
#warning "Note: using x86-64 inline assembly for YESCRYPT_RW.  That's great."
#define PWXFORM_SIMD(X) { \
	__m128i H; \
	__asm__( \
	    "movd %0, %%rax\n\t" \
	    "pshufd $0xb1, %0, %1\n\t" \
	    "andq %2, %%rax\n\t" \
	    "pmuludq %1, %0\n\t" \
	    "movl %%eax, %%ecx\n\t" \
	    "shrq $0x20, %%rax\n\t" \
	    "paddq (%3,%%rcx), %0\n\t" \
	    "pxor (%4,%%rax), %0\n\t" \
	    : "+x" (X), "=x" (H) \
	    : "d" (Smask2), "S" (S0), "D" (S1) \
	    : "cc", "ax", "cx"); \
}
#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit with SSE4.1 */
#define PWXFORM_SIMD(X) { \
	__m128i x = _mm_and_si128(X, _mm_set1_epi64x(Smask2)); \
	__m128i s0 = *(__m128i *)(S0 + (uint32_t)_mm_cvtsi128_si32(x)); \
	__m128i s1 = *(__m128i *)(S1 + (uint32_t)_mm_extract_epi32(x, 1)); \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, s0); \
	X = _mm_xor_si128(X, s1); \
}
#else
/* 32-bit without SSE4.1 */
#define PWXFORM_SIMD(X) { \
	uint64_t x = EXTRACT64(X) & Smask2; \
	__m128i s0 = *(__m128i *)(S0 + (uint32_t)x); \
	__m128i s1 = *(__m128i *)(S1 + (x >> 32)); \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, s0); \
	X = _mm_xor_si128(X, s1); \
}
#endif

#define PWXFORM_ROUND \
	PWXFORM_SIMD(X0) \
	PWXFORM_SIMD(X1) \
	PWXFORM_SIMD(X2) \
	PWXFORM_SIMD(X3)

/*
 * This offset helps address the 256-byte write block via the single-byte
 * displacements encodable in x86(-64) instructions.  It is needed because the
 * displacements are signed.  Without it, we'd get 4-byte displacements for
 * half of the writes.  Setting it to 0x80 instead of 0x78 would avoid needing
 * a displacement for one of the writes, but then the LEA instruction would
 * need a 4-byte displacement.
 */
#define PWXFORM_WRITE_OFFSET 0x78

#define PWXFORM_WRITE \
	*(__m128i *)(Sw - PWXFORM_WRITE_OFFSET) = X0; \
	*(__m128i *)(Sw - PWXFORM_WRITE_OFFSET + 16) = X1; \
	*(__m128i *)(Sw - PWXFORM_WRITE_OFFSET + 32) = X2; \
	*(__m128i *)(Sw - PWXFORM_WRITE_OFFSET + 48) = X3; \
	Sw += 64;

#if defined(__x86_64__) && defined(__GNUC__) && !defined(__ICC)
#define FORCE_REGALLOC_3 __asm__("" : : "b" (Sw));
#else
#define FORCE_REGALLOC_3 /* empty */
#endif

#define PWXFORM { \
	uint8_t *Sw = S2 + w + PWXFORM_WRITE_OFFSET; \
	FORCE_REGALLOC_3 \
	PWXFORM_ROUND \
	PWXFORM_ROUND PWXFORM_WRITE \
	PWXFORM_ROUND PWXFORM_WRITE \
	PWXFORM_ROUND PWXFORM_WRITE \
	PWXFORM_ROUND PWXFORM_WRITE \
	PWXFORM_ROUND \
	w = (w + 64 * 4) & Smask2; \
	{ \
		uint8_t *Stmp = S2; \
		S2 = S1; \
		S1 = S0; \
		S0 = Stmp; \
	} \
}

#define OUT(out) \
	(out).q[0] = X0; \
	(out).q[1] = X1; \
	(out).q[2] = X2; \
	(out).q[3] = X3;

typedef struct {
	uint8_t *S0, *S1, *S2;
	size_t w;
} pwxform_ctx_t;

#define Salloc (Sbytes + ((sizeof(pwxform_ctx_t) + 63) & ~63U))

/**
 * blockmix_pwxform(Bin, Bout, r, S):
 * Compute Bout = BlockMix_pwxform{salsa20/8, r, S}(Bin).  The input Bin must
 * be 128r bytes in length; the output Bout must also be the same size.
 */
static void blockmix(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r, pwxform_ctx_t *restrict ctx)
{
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1, *S2 = ctx->S2;
	size_t w = ctx->w;
	size_t i;
	DECL_X

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

	READ_X(Bin[r])

	DECL_SMASK2REG

	i = 0;
	do {
		XOR4(Bin[i])
		PWXFORM
		if (unlikely(i >= r))
			break;
		OUT(Bout[i])
		i++;
	} while (1);

	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;

	SALSA20_2(Bout[i])
}

static uint32_t blockmix_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    size_t r, int Bin2_in_ROM, pwxform_ctx_t *restrict ctx)
{
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1, *S2 = ctx->S2;
	size_t w = ctx->w;
	size_t i;
	DECL_X

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

	if (Bin2_in_ROM) {
		PREFETCH(&Bin2[r], _MM_HINT_NTA)
		for (i = 0; i < r; i++) {
			PREFETCH(&Bin2[i], _MM_HINT_NTA)
		}
	} else {
		PREFETCH(&Bin2[r], _MM_HINT_T0)
		for (i = 0; i < r; i++) {
			PREFETCH(&Bin2[i], _MM_HINT_T0)
		}
	}

	XOR4_2(Bin1[r], Bin2[r])

	DECL_SMASK2REG

	i = 0;
	r--;
	do {
		XOR4(Bin1[i])
		XOR4(Bin2[i])
		PWXFORM
		OUT(Bout[i])

		XOR4(Bin1[i + 1])
		XOR4(Bin2[i + 1])
		PWXFORM

		if (unlikely(i >= r))
			break;

		OUT(Bout[i + 1])

		i += 2;
	} while (1);
	i++;

	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;

	SALSA20_2(Bout[i])

	return INTEGERIFY(X0);
}

#undef XOR4
#define XOR4(in, out) \
	(out).q[0] = Y0 = _mm_xor_si128((in).q[0], (out).q[0]); \
	(out).q[1] = Y1 = _mm_xor_si128((in).q[1], (out).q[1]); \
	(out).q[2] = Y2 = _mm_xor_si128((in).q[2], (out).q[2]); \
	(out).q[3] = Y3 = _mm_xor_si128((in).q[3], (out).q[3]);

#define XOR4_Y \
	X0 = _mm_xor_si128(X0, Y0); \
	X1 = _mm_xor_si128(X1, Y1); \
	X2 = _mm_xor_si128(X2, Y2); \
	X3 = _mm_xor_si128(X3, Y3);

static uint32_t blockmix_xor_save(const salsa20_blk_t *restrict Bin1,
    salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    size_t r, pwxform_ctx_t *restrict ctx)
{
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1, *S2 = ctx->S2;
	size_t w = ctx->w;
	size_t i;
	DECL_X
	DECL_Y

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

	PREFETCH(&Bin2[r], _MM_HINT_T0)
	for (i = 0; i < r; i++) {
		PREFETCH(&Bin2[i], _MM_HINT_T0)
	}

	XOR4_2(Bin1[r], Bin2[r])

	DECL_SMASK2REG

	i = 0;
	r--;
	do {
		XOR4(Bin1[i], Bin2[i])
		XOR4_Y
		PWXFORM
		OUT(Bout[i])

		XOR4(Bin1[i + 1], Bin2[i + 1])
		XOR4_Y
		PWXFORM

		if (unlikely(i >= r))
			break;

		OUT(Bout[i + 1])

		i += 2;
	} while (1);
	i++;

	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;

	SALSA20_2(Bout[i])

	return INTEGERIFY(X0);
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static inline uint32_t integerify(const salsa20_blk_t *B, size_t r)
{
	return B[2 * r - 1].w[0];
}

/**
 * smix1(B, r, N, flags, V, NROM, VROM, XY, ctx):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 128r bytes in length.  The value N must be even and no
 * smaller than 2.  The array V must be aligned to a multiple of 64 bytes, and
 * arrays B and XY to a multiple of at least 16 bytes (aligning them to 64
 * bytes as well saves cache lines, but might result in cache bank conflicts).
 */
static void smix1(uint8_t *B, size_t r, uint32_t N, yescrypt_flags_t flags,
    salsa20_blk_t *V, uint32_t NROM, const salsa20_blk_t *VROM,
    salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 2 * r;
	salsa20_blk_t *X = V, *Y;
	uint32_t i, j;
	size_t k;

	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			X[k].w[i] = le32dec(&B[(k * 16 + (i * 5 % 16)) * 4]);
		}
	}

	if (VROM) {
		uint32_t n;
		salsa20_blk_t *V_n;
		const salsa20_blk_t *V_j;

		V_j = &VROM[(NROM - 1) * s];
		Y = &V[s];
		j = blockmix_xor(X, V_j, Y, r, 1, ctx) & (NROM - 1);
		V_j = &VROM[j * s];
		X = &V[2 * s];
		j = blockmix_xor(Y, V_j, X, r, 1, ctx);

		for (n = 2; n < N; n <<= 1) {
			uint32_t m = (n < N / 2) ? n : (N - 1 - n);
			V_n = &V[n * s];
			for (i = 1; i < m; i += 2) {
				j &= n - 1;
				j += i - 1;
				V_j = &V[j * s];
				Y = &V_n[i * s];
				j = blockmix_xor(X, V_j, Y, r, 0, ctx) & (NROM - 1);
				V_j = &VROM[j * s];
				X = &V_n[(i + 1) * s];
				j = blockmix_xor(Y, V_j, X, r, 1, ctx);
			}
		}
		n >>= 1;

		j &= n - 1;
		j += N - 2 - n;
		V_j = &V[j * s];
		Y = &V[(N - 1) * s];
		j = blockmix_xor(X, V_j, Y, r, 0, ctx) & (NROM - 1);
		V_j = &VROM[j * s];
		X = XY;
		blockmix_xor(Y, V_j, X, r, 1, ctx);
	} else if (flags & YESCRYPT_RW) {
		uint32_t n;
		salsa20_blk_t *V_n, *V_j;

		Y = &V[s];
		blockmix(X, Y, r, ctx);
		X = &V[2 * s];
		blockmix(Y, X, r, ctx);
		j = integerify(X, r);

		for (n = 2; n < N; n <<= 1) {
			uint32_t m = (n < N / 2) ? n : (N - 1 - n);
			V_n = &V[n * s];
			for (i = 1; i < m; i += 2) {
				Y = &V_n[i * s];
				j &= n - 1;
				j += i - 1;
				V_j = &V[j * s];
				j = blockmix_xor(X, V_j, Y, r, 0, ctx);
				j &= n - 1;
				j += i;
				V_j = &V[j * s];
				X = &V_n[(i + 1) * s];
				j = blockmix_xor(Y, V_j, X, r, 0, ctx);
			}
		}
		n >>= 1;

		j &= n - 1;
		j += N - 2 - n;
		V_j = &V[j * s];
		Y = &V[(N - 1) * s];
		j = blockmix_xor(X, V_j, Y, r, 0, ctx);
		j &= n - 1;
		j += N - 1 - n;
		V_j = &V[j * s];
		X = XY;
		blockmix_xor(Y, V_j, X, r, 0, ctx);
	} else {
		for (i = 1; i < N - 1; i += 2) {
			Y = &V[i * s];
			blockmix_salsa8(X, Y, r);
			X = &V[(i + 1) * s];
			blockmix_salsa8(Y, X, r);
		}

		Y = &V[i * s];
		blockmix_salsa8(X, Y, r);
		X = XY;
		blockmix_salsa8(Y, X, r);
	}

	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			le32enc(&B[(k * 16 + (i * 5 % 16)) * 4], X[k].w[i]);
		}
	}
}

/**
 * smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, ctx):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  The value N must be a power of 2
 * greater than 1.  The value Nloop must be even.  The array V must be aligned
 * to a multiple of 64 bytes, and arrays B and XY to a multiple of at least 16
 * bytes (aligning them to 64 bytes as well saves cache lines, but might result
 * in cache bank conflicts).
 */
static void smix2(uint8_t *B, size_t r, uint32_t N, uint64_t Nloop,
    yescrypt_flags_t flags, salsa20_blk_t *V, uint32_t NROM,
    const salsa20_blk_t *VROM, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 2 * r;
	salsa20_blk_t *X = XY, *Y = &XY[s];
	uint32_t i, j;
	size_t k;

	if (Nloop == 0)
		return;

	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			X[k].w[i] = le32dec(&B[(k * 16 + (i * 5 % 16)) * 4]);
		}
	}

	j = integerify(X, r) & (N - 1);

/*
 * Normally, VROM implies YESCRYPT_RW, but we check for these separately
 * because our SMix resets YESCRYPT_RW for the smix2() calls operating on the
 * entire V when p > 1.
 */
	if (VROM && (flags & YESCRYPT_RW)) {
		do {
			salsa20_blk_t *V_j = &V[j * s];
			const salsa20_blk_t *VROM_j;
			j = blockmix_xor_save(X, V_j, Y, r, ctx) & (NROM - 1);
			VROM_j = &VROM[j * s];
			j = blockmix_xor(Y, VROM_j, X, r, 1, ctx) & (N - 1);
		} while (Nloop -= 2);
	} else if (VROM) {
		do {
			const salsa20_blk_t *V_j = &V[j * s];
			j = blockmix_xor(X, V_j, Y, r, 0, ctx) & (NROM - 1);
			V_j = &VROM[j * s];
			j = blockmix_xor(Y, V_j, X, r, 1, ctx) & (N - 1);
		} while (Nloop -= 2);
	} else if (flags & YESCRYPT_RW) {
		do {
			salsa20_blk_t *V_j = &V[j * s];
			j = blockmix_xor_save(X, V_j, Y, r, ctx) & (N - 1);
			V_j = &V[j * s];
			j = blockmix_xor_save(Y, V_j, X, r, ctx) & (N - 1);
		} while (Nloop -= 2);
	} else if (ctx) {
		do {
			const salsa20_blk_t *V_j = &V[j * s];
			j = blockmix_xor(X, V_j, Y, r, 0, ctx) & (N - 1);
			V_j = &V[j * s];
			j = blockmix_xor(Y, V_j, X, r, 0, ctx) & (N - 1);
		} while (Nloop -= 2);
	} else {
		do {
			const salsa20_blk_t *V_j = &V[j * s];
			j = blockmix_salsa8_xor(X, V_j, Y, r) & (N - 1);
			V_j = &V[j * s];
			j = blockmix_salsa8_xor(Y, V_j, X, r) & (N - 1);
		} while (Nloop -= 2);
	}

	for (k = 0; k < 2 * r; k++) {
		for (i = 0; i < 16; i++) {
			le32enc(&B[(k * 16 + (i * 5 % 16)) * 4], X[k].w[i]);
		}
	}
}

/**
 * p2floor(x):
 * Largest power of 2 not greater than argument.
 */
static uint64_t p2floor(uint64_t x)
{
	uint64_t y;
	while ((y = x & (x - 1)))
		x = y;
	return x;
}

/**
 * smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S, passwd):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage XY
 * must be 256r or 256rp bytes in length (the larger size is required with
 * OpenMP-enabled builds).  The value N must be a power of 2 greater than 1.
 * The array V must be aligned to a multiple of 64 bytes, and arrays B and
 * XY to a multiple of at least 16 bytes (aligning them to 64 bytes as well
 * saves cache lines and helps avoid false sharing in OpenMP-enabled builds
 * when p > 1, but it might also result in cache bank conflicts).
 */
static void smix(uint8_t *B, size_t r, uint32_t N, uint32_t p, uint32_t t,
    yescrypt_flags_t flags,
    salsa20_blk_t *V, uint32_t NROM, const salsa20_blk_t *VROM,
    salsa20_blk_t *XY, uint8_t *S, uint8_t *passwd)
{
	size_t s = 2 * r;
	uint32_t Nchunk;
	uint64_t Nloop_all, Nloop_rw;
	uint32_t i;

	Nchunk = N / p;
	Nloop_all = Nchunk;
	if (flags & YESCRYPT_RW) {
		if (t <= 1) {
			if (t)
				Nloop_all *= 2; /* 2/3 */
			Nloop_all = (Nloop_all + 2) / 3; /* 1/3, round up */
		} else {
			Nloop_all *= t - 1;
		}
	} else if (t) {
		if (t == 1)
			Nloop_all += (Nloop_all + 1) / 2; /* 1.5, round up */
		Nloop_all *= t;
	}

	Nloop_rw = 0;
	if (flags & YESCRYPT_INIT_SHARED)
		Nloop_rw = Nloop_all;
	else if (flags & YESCRYPT_RW)
		Nloop_rw = Nloop_all / p;

	Nchunk &= ~(uint32_t)1; /* round down to even */
	Nloop_all++; Nloop_all &= ~(uint64_t)1; /* round up to even */
	Nloop_rw++; Nloop_rw &= ~(uint64_t)1; /* round up to even */

#ifdef _OPENMP
#pragma omp parallel if (p > 1) default(none) private(i) shared(B, r, N, p, flags, V, NROM, VROM, XY, S, passwd, s, Nchunk, Nloop_all, Nloop_rw)
	{
#pragma omp for
#endif
	for (i = 0; i < p; i++) {
		uint32_t Vchunk = i * Nchunk;
		uint32_t Np = (i < p - 1) ? Nchunk : (N - Vchunk);
		uint8_t *Bp = &B[128 * r * i];
		salsa20_blk_t *Vp = &V[Vchunk * s];
#ifdef _OPENMP
		salsa20_blk_t *XYp = &XY[i * (2 * s)];
#else
		salsa20_blk_t *XYp = XY;
#endif
		pwxform_ctx_t *ctx_i = NULL;
		if (flags & YESCRYPT_RW) {
			uint8_t *Si = S + i * Salloc;
			smix1(Bp, 1, Sbytes / 128, 0 /* no flags */,
			    (salsa20_blk_t *)Si, 0, NULL, XYp, NULL);
			ctx_i = (pwxform_ctx_t *)(Si + Sbytes);
			ctx_i->S2 = Si;
			ctx_i->S1 = Si + Sbytes / 3;
			ctx_i->S0 = Si + Sbytes / 3 * 2;
			ctx_i->w = 0;
			if (i == 0)
				HMAC_SHA256_Buf(Bp + (128 * r - 64), 64,
				    passwd, 32, passwd);
		}
		smix1(Bp, r, Np, flags, Vp, NROM, VROM, XYp, ctx_i);
		smix2(Bp, r, p2floor(Np), Nloop_rw, flags, Vp,
		    NROM, VROM, XYp, ctx_i);
	}

	if (Nloop_all > Nloop_rw) {
#ifdef _OPENMP
#pragma omp for
#endif
		for (i = 0; i < p; i++) {
			uint8_t *Bp = &B[128 * r * i];
#ifdef _OPENMP
			salsa20_blk_t *XYp = &XY[i * (2 * s)];
#else
			salsa20_blk_t *XYp = XY;
#endif
			pwxform_ctx_t *ctx_i = NULL;
			if (flags & YESCRYPT_RW) {
				uint8_t *Si = S + i * Salloc;
				ctx_i = (pwxform_ctx_t *)(Si + Sbytes);
			}
			smix2(Bp, r, N, Nloop_all - Nloop_rw,
			    flags & ~YESCRYPT_RW, V, NROM, VROM, XYp, ctx_i);
		}
	}
#ifdef _OPENMP
	}
#endif
}

/**
 * yescrypt_kdf_body(shared, local, passwd, passwdlen, salt, saltlen,
 *     flags, N, r, p, t, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen), or a revision of scrypt as requested by flags and shared, and
 * write the result into buf.
 *
 * shared and flags may request special modes as described in yescrypt.h.
 *
 * local is the thread-local data structure, allowing to preserve and reuse a
 * memory allocation across calls, thereby reducing its overhead.
 *
 * t controls computation time while not affecting peak memory usage.
 *
 * Return 0 on success; or -1 on error.
 *
 * This optimized implementation currently limits N to the range from 4 to
 * 2^31, but other implementations might not.
 */
static int yescrypt_kdf_body(const yescrypt_shared_t *shared,
    yescrypt_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    yescrypt_flags_t flags, uint64_t N, uint32_t r, uint32_t p, uint32_t t,
    uint64_t NROM,
    uint8_t *buf, size_t buflen)
{
	yescrypt_region_t tmp;
	const salsa20_blk_t *VROM;
	size_t B_size, V_size, XY_size, need;
	uint8_t *B, *S;
	salsa20_blk_t *V, *XY;
	uint8_t sha256[32];
	uint8_t dk[sizeof(sha256)], *dkp = buf;

	/* Sanity-check parameters */
	switch (flags & YESCRYPT_MODE_MASK) {
	case 0: /* classic scrypt - can't have anything non-standard */
		if (flags || t || NROM)
			goto out_EINVAL;
		break;
	case YESCRYPT_WORM:
		if (flags != YESCRYPT_WORM || NROM)
			goto out_EINVAL;
		break;
	case YESCRYPT_RW:
		if (flags != (flags & YESCRYPT_KNOWN_FLAGS))
			goto out_EINVAL;
#if PWXsimple == 2 && PWXgather == 4 && Sbytes == 12288
		if ((flags & YESCRYPT_RW_FLAVOR_MASK) ==
		    (YESCRYPT_ROUNDS_6 | YESCRYPT_GATHER_4 |
		    YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K))
			break;
#else
#error "Unsupported pwxform settings"
#endif
		/* FALLTHRU */
	default:
		goto out_EINVAL;
	}
#if SIZE_MAX > UINT32_MAX
	if (buflen > (((uint64_t)1 << 32) - 1) * 32)
		goto out_EINVAL;
#endif
	if ((uint64_t)r * (uint64_t)p >= 1 << 30)
		goto out_EINVAL;
	if (N > UINT32_MAX)
		goto out_EINVAL;
	if ((N & (N - 1)) != 0 || N <= 3 || r < 1 || p < 1)
		goto out_EINVAL;
	if (r > SIZE_MAX / 256 / p ||
	    N > SIZE_MAX / 128 / r)
		goto out_EINVAL;
	if (flags & YESCRYPT_RW) {
		if (N / p <= 3 || p > SIZE_MAX / Salloc)
			goto out_EINVAL;
	}
#ifdef _OPENMP
	else if (N > SIZE_MAX / 128 / (r * p))
		goto out_EINVAL;
#endif

	VROM = NULL;
	if (shared) {
		uint64_t expected_size = (size_t)128 * r * NROM;
		if ((NROM & (NROM - 1)) != 0 ||
		    NROM <= 1 || NROM > UINT32_MAX ||
		    shared->aligned_size < expected_size)
			goto out_EINVAL;
		if (!(flags & YESCRYPT_INIT_SHARED)) {
			uint64_t *tag = (uint64_t *)
			    ((uint8_t *)shared->aligned + expected_size - 48);
			if (tag[0] != YESCRYPT_ROM_TAG1 || tag[1] != YESCRYPT_ROM_TAG2)
				goto out_EINVAL;
		}
		VROM = shared->aligned;
	} else {
		if (NROM)
			goto out_EINVAL;
	}

	/* Allocate memory */
	V = NULL;
	V_size = (size_t)128 * r * N;
#ifdef _OPENMP
	if (!(flags & YESCRYPT_RW))
		V_size *= p;
#endif
	need = V_size;
	if (flags & YESCRYPT_INIT_SHARED) {
		if (local->aligned_size < need) {
			if (local->base || local->aligned ||
			    local->base_size || local->aligned_size)
				goto out_EINVAL;
			if (!alloc_region(local, need))
				return -1;
		}
		if (flags & YESCRYPT_ALLOC_ONLY)
			return -2; /* expected "failure" */
		V = (salsa20_blk_t *)local->aligned;
		need = 0;
	}
	B_size = (size_t)128 * r * p;
	need += B_size;
	if (need < B_size)
		goto out_EINVAL;
	XY_size = (size_t)256 * r;
#ifdef _OPENMP
	XY_size *= p;
#endif
	need += XY_size;
	if (need < XY_size)
		goto out_EINVAL;
	if (flags & YESCRYPT_RW) {
		size_t S_size = (size_t)Salloc * p;
		need += S_size;
		if (need < S_size)
			goto out_EINVAL;
	}
	if (flags & YESCRYPT_INIT_SHARED) {
		if (!alloc_region(&tmp, need))
			return -1;
		B = (uint8_t *)tmp.aligned;
		XY = (salsa20_blk_t *)((uint8_t *)B + B_size);
	} else {
		init_region(&tmp);
		if (local->aligned_size < need) {
			if (free_region(local))
				return -1;
			if (!alloc_region(local, need))
				return -1;
		}
		if (flags & YESCRYPT_ALLOC_ONLY)
			return -3; /* expected "failure" */
		B = (uint8_t *)local->aligned;
		V = (salsa20_blk_t *)((uint8_t *)B + B_size);
		XY = (salsa20_blk_t *)((uint8_t *)V + V_size);
	}
	S = NULL;
	if (flags & YESCRYPT_RW)
		S = (uint8_t *)XY + XY_size;

	if (flags) {
		HMAC_SHA256_Buf("yescrypt-prehash",
		    (flags & YESCRYPT_PREHASH) ? 16 : 8,
		    passwd, passwdlen, sha256);
		passwd = sha256;
		passwdlen = sizeof(sha256);
	}

	PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, B, B_size);

	if (flags)
		memcpy(sha256, B, sizeof(sha256));

	if (p == 1 || (flags & YESCRYPT_RW)) {
		smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S, sha256);
	} else {
		uint32_t i;
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(B, r, N, p, t, flags, V, NROM, VROM, XY, S)
#endif
		for (i = 0; i < p; i++) {
#ifdef _OPENMP
			smix(&B[(size_t)128 * r * i], r, N, 1, t, flags,
			    &V[(size_t)2 * r * i * N],
			    NROM, VROM,
			    &XY[(size_t)4 * r * i], NULL, NULL);
#else
			smix(&B[(size_t)128 * r * i], r, N, 1, t, flags, V,
			    NROM, VROM, XY, NULL, NULL);
#endif
		}
	}

	dkp = buf;
	if (flags && buflen < sizeof(dk)) {
		PBKDF2_SHA256(passwd, passwdlen, B, B_size, 1, dk, sizeof(dk));
		dkp = dk;
	}

	PBKDF2_SHA256(passwd, passwdlen, B, B_size, 1, buf, buflen);

	/*
	 * Except when computing classic scrypt, allow all computation so far
	 * to be performed on the client.  The final steps below match those of
	 * SCRAM (RFC 5802), so that an extension of SCRAM (with the steps so
	 * far in place of SCRAM's use of PBKDF2 and with SHA-256 in place of
	 * SCRAM's use of SHA-1) would be usable with yescrypt hashes.
	 */
	if (flags && !(flags & YESCRYPT_PREHASH)) {
		/* Compute ClientKey */
		HMAC_SHA256_Buf(dkp, sizeof(dk), "Client Key", 10, sha256);
		/* Compute StoredKey */
		{
			size_t clen = buflen;
			if (clen > sizeof(dk))
				clen = sizeof(dk);
			SHA256_Buf(sha256, sizeof(sha256), dk);
			memcpy(buf, dk, clen);
		}
	}

	if (flags) {
		insecure_memzero(sha256, sizeof(sha256));
		insecure_memzero(dk, sizeof(dk));
	}

	if (free_region(&tmp)) {
		insecure_memzero(buf, buflen); /* must preserve errno */
		return -1;
	}

	/* Success! */
	return 0;

out_EINVAL:
	errno = EINVAL;
	return -1;
}

/**
 * yescrypt_kdf(shared, local, passwd, passwdlen, salt, saltlen, params,
 *     buf, buflen):
 * Compute scrypt or its revision as requested by the parameters.  The inputs
 * to this function are the same as those for yescrypt_kdf_body() above, with
 * the addition of g, which controls hash upgrades (0 for no upgrades so far).
 */
int yescrypt_kdf(const yescrypt_shared_t *shared, yescrypt_local_t *local,
    const uint8_t *passwd, size_t passwdlen,
    const uint8_t *salt, size_t saltlen,
    const yescrypt_params_t *params,
    uint8_t *buf, size_t buflen)
{
	yescrypt_flags_t flags = params->flags;
	uint64_t N = params->N;
	uint32_t r = params->r;
	uint32_t p = params->p;
	uint32_t t = params->t;
	uint32_t g = params->g;
	uint64_t NROM = params->NROM;
	uint8_t dk[32];
	int retval;

	/* Support for hash upgrades has been temporarily removed */
	if (g) {
		errno = EINVAL;
		return -1;
	}

	if ((flags & (YESCRYPT_RW | YESCRYPT_INIT_SHARED)) == YESCRYPT_RW &&
	    p >= 1 && N / p >= 0x100 && N / p * r >= 0x20000) {
		if (yescrypt_kdf_body(shared, local,
		    passwd, passwdlen, salt, saltlen,
		    flags | YESCRYPT_ALLOC_ONLY, N, r, p, t, NROM,
		    buf, buflen) != -3) {
			errno = EINVAL;
			return -1;
		}
		if ((retval = yescrypt_kdf_body(shared, local,
		    passwd, passwdlen, salt, saltlen,
		    flags | YESCRYPT_PREHASH, N >> 6, r, p, 0, NROM,
		    dk, sizeof(dk))))
			return retval;
		passwd = dk;
		passwdlen = sizeof(dk);
	}

	retval = yescrypt_kdf_body(shared, local,
	    passwd, passwdlen, salt, saltlen,
	    flags, N, r, p, t, NROM, buf, buflen);
	if (passwd == dk)
		insecure_memzero(dk, sizeof(dk));
	return retval;
}
