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
	yescrypt_params_t params = { .flags = YESCRYPT_DEFAULTS,
		.N = 4096, .r = 32, .p = 1 };

	if (count) {
		/* `1 << (count - 1)` is MiB usage in range of 1MiB..1GiB,
		 * thus, count is in range of 1..11 */
		if (count <= 2) {
			params.r = 8; /* N in 1KiB */
			params.N = 512 << count;
		} else if (count <= 11) {
			params.r = 32; /* N in 4KiB */
			params.N = 128 << count;
		} else {
			if (output_size > 0)
				output[0] = '\0';
			__set_errno(EINVAL);
			return NULL;
		}
	}

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

	if (yescrypt_init_local(&local)) {
		__set_errno(ENOMEM);
		return NULL;
	}
	retval = yescrypt_r(NULL, &local,
	    (const uint8_t *)passwd, strlen(passwd),
	    (const uint8_t *)setting, NULL,
	    (uint8_t *)output, size);
	if (yescrypt_free_local(&local)) {
		__set_errno(ENOMEM);
		return NULL;
	}
	if (!retval)
		__set_errno(EINVAL);
	return (char *)retval;
}

