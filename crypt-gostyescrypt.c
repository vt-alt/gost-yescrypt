/*
 * (c) 2018, vt@altlinux.org
 *
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2018 vt@altlinux.org and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#ifndef __set_errno
# define __set_errno(val) errno = (val)
#endif
#define YESCRYPT_INTERNAL
#include "yescrypt.h"
#include "yescrypt-common.c"
#include "crypt-yescrypt.h"
#include "gosthash2012.h"

/* GOST2012_256 */
void gost_hash256(const uint8_t *t, size_t n, uint8_t *out32)
{
	const unsigned int BITS = 256;
	gost2012_hash_ctx ctx;

	init_gost2012_hash_ctx(&ctx, BITS);
	gost2012_hash_block(&ctx, t, n);
	gost2012_finish_hash(&ctx, out32);
}

/* HMAC_GOSTR3411_2012_256 */
void gost_hmac256(const uint8_t *k, size_t n, const uint8_t *t, size_t len, uint8_t *out32)
{
	const unsigned int L = 32; /* hash output len */
	const unsigned int B = 64; /* hash input len (512) */
	const unsigned int BITS = L * 8; /* 256 */
	gost2012_hash_ctx ctx;
	unsigned char pad[B]; /* ipad and opad */
	unsigned char kstar[B]; /* derived key */
	unsigned char digest[L];
	int i;

	/* P 50.1.113-2016 only allowed n to be in range 256..512 */
	if (n >= L && n <= B) {
		for (i = 0; i < sizeof(pad); i++)
			kstar[i] = i < n ? k[i] : 0;
	} else
		abort();

	init_gost2012_hash_ctx(&ctx, BITS);
	for (i = 0; i < sizeof(pad); i++)
		pad[i] = kstar[i] ^ 0x36; /* ipad */
	gost2012_hash_block(&ctx, pad, sizeof(pad));
	gost2012_hash_block(&ctx, t, len);
	gost2012_finish_hash(&ctx, digest);

	init_gost2012_hash_ctx(&ctx, BITS);
	for (i = 0; i < sizeof(pad); i++)
		pad[i] = kstar[i] ^ 0x5c; /* opad */
	gost2012_hash_block(&ctx, pad, sizeof(pad));
	gost2012_hash_block(&ctx, digest, sizeof(digest));
	gost2012_finish_hash(&ctx, out32);
}

char *_crypt_gensalt_gostyescrypt_rn(const char *prefix, unsigned long count,
    const char *input, int input_size, char *output, int output_size)
{
	if (prefix &&
	    (prefix[0] != '$' ||
	     prefix[1] != 'g' ||
	     prefix[2] != 'y' ||
	     prefix[3] != '$')) {
		if (output_size > 0)
			output[0] = '\0';
		__set_errno(EINVAL);
		return NULL;
	}

	if (!_crypt_gensalt_yescrypt_rn(NULL, count,
		    input, input_size,
		    output, output_size)) {
		return NULL;
	}

	/* need to expand prefix by 1 char to insert gost marker */
	int saltlen = strlen(output);
	if (saltlen + 2 > output_size) {
		if (output_size > 0)
			output[0] = '\0';
		__set_errno(ERANGE);
		return NULL;
	}
	memmove(output + 1, output, saltlen + 1);
	output[1] = 'g'; /* prepend yescrypt marker with gost marker */

	return output;
}

char *_crypt_gostyescrypt_rn(const char *passwd, const char *setting, char *output, int size)
{
	yescrypt_local_t local;
	uint8_t *retval;

	if (!output ||
	    size < 2 ||
	    !setting ||
	    yescrypt_init_local(&local)) {
		__set_errno(ENOMEM);
		return NULL;
	}

	/* convert gost setting to yescrypt setting */
	char *gsetting = malloc(strlen(setting) + 1);
	if (!gsetting) {
		__set_errno(ENOMEM);
		yescrypt_free_local(&local);
		return NULL;
	}
	gsetting[0] = '$';
	gsetting[1] = 'y';
	gsetting[2] = '$';
	memcpy(&gsetting[3], setting + 4, strlen(setting) - 3);

	retval = yescrypt_r(NULL, &local,
	    (const uint8_t *)passwd, strlen(passwd),
	    (const uint8_t *)gsetting, NULL,
	    (uint8_t *)output + 1, size - 1);

	free(gsetting);
	gsetting = NULL;
	if (yescrypt_free_local(&local)) {
		__set_errno(ENOMEM);
		return NULL;
	}
	if (!retval) {
		__set_errno(EINVAL);
		return NULL;
	}
	output[0] = '$';
	output[1] = 'g';

	/* extract yescrypt output from "$y$param$salt$output" */
	char *hptr = strchr((const char *)retval + 3, '$');
	if (!hptr) {
		__set_errno(EINVAL);
		return NULL;
	}
	hptr = strchr(hptr + 1, '$');
	if (!hptr) {
		__set_errno(EINVAL);
		return NULL;
	}
	hptr++; /* start of output */

	/* decode yescrypt output into its raw 256-bit form */
	uint8_t y[32]; /* 256 bit */
	size_t ylen = sizeof(y);
	if (!decode64(y, &ylen, (uint8_t *)hptr, strlen(hptr)) ||
	    ylen != sizeof(y)) {
		__set_errno(EINVAL);
		return NULL;
	}

	/*
	 * HMAC_GOSTR3411_2012_256(GOST2012_256(K), yescrypt(K))
	 * yescrypt output is used in place of message
	 * thus, its crypto properties are superseded by GOST
	 * password is always hashed for hmac to avoid collisions
	 */
	uint8_t hk[32];
	gost_hash256((uint8_t *)passwd, strlen(passwd), hk);
	gost_hmac256(hk, sizeof(hk), y, sizeof(y), y);

	encode64((uint8_t *)hptr, size - (hptr - output), y, sizeof(y));

	return output;
}

