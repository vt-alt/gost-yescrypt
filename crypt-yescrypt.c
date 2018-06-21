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
#include "yescrypt.h"

char *_crypt_gensalt_yescrypt_rn(const char *prefix, unsigned long count,
    const char *input, int input_size, char *output, int output_size)
{
	if (prefix[0] != '$' || prefix[1] != 'y' || prefix[2] != '$') {
		if (output_size > 0)
			output[0] = '\0';
		__set_errno(EINVAL);
		return NULL;
	}

	/* use as 'low default' one of recommended parameter sets */
	yescrypt_params_t params = { .flags = YESCRYPT_DEFAULTS, .N = 4096, .r = 32, .p = 1 };

	if (count) {
		/* 'Simply double the value of N as many times as needed.  Since N must be a
		 * power of two, you may use r (in the range of 8 to 32) or/and t (in the
		 * range of 0 to 2) for fine-tuning the running time, but first bring N to
		 * the maximum you can afford.' */
		uint32_t nn = count & 0x3f;
		if (nn < 2)
			nn = 2;
		if (nn > 48)
			nn = 48;
		params.N = 1LL << nn;
		uint32_t rr = (count >> 6) & 0x3f;
		if (rr < 8)
			rr = 8;
		if (rr > 32)
			rr = 32;
		params.r = rr;
		uint32_t tt = count >> (6 + 6);
		if (tt > 2)
			tt = 2;
		params.t = tt;
	}
#if 0
	printf(": yescrypt_encode_params_r(flags=%#x, N=%lu, r=%u, t=%u, p=%u)\n",
	    params.flags, params.N, params.r, params.t, params.p);
#endif

	if (!yescrypt_encode_params_r(&params, (const uint8_t *)input, input_size,
		    (uint8_t *)output, output_size)) {
		if (output_size > 0)
			output[0] = '\0';
		__set_errno(ERANGE);
		return NULL;
	}

	return output;
}

char *_crypt_yescrypt_rn(const char *passwd, const char *setting, char *output, int size)
{
	yescrypt_local_t local;
	uint8_t *retval;

	if (yescrypt_init_local(&local))
		return NULL;
	retval = yescrypt_r(NULL, &local,
	    (const uint8_t *)passwd, strlen(passwd),
	    (const uint8_t *)setting, NULL,
	    (uint8_t *)output, size);
	if (yescrypt_free_local(&local))
		return NULL;
	return (char *)retval;
}

