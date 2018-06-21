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

#ifndef _CRYPT_YESCRYPT_H_
#define _CRYPT_YESCRYPT_H_

char *_crypt_gensalt_yescrypt_rn(const char *prefix, unsigned long count,
    const char *input, int input_size, char *output, int output_size);

#endif
