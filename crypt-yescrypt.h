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

char *_crypt_yescrypt_rn(const char *passwd, const char *setting, char *output, int size);

/* crypt-gostyescrypt.c */
void gost_hash256(const uint8_t *t, size_t n, uint8_t *out32);
void gost_hmac256(const uint8_t *k, size_t n, const uint8_t *t, size_t len, uint8_t *out32);

char *_crypt_gensalt_gostyescrypt_rn(const char *prefix, unsigned long count,
    const char *input, int input_size, char *output, int output_size);

char *_crypt_gostyescrypt_rn(const char *passwd, const char *setting, char *output, int size);

/* yescrypt-common.c */
const uint8_t *decode64(uint8_t *dst, size_t *dstlen, const uint8_t *src, size_t srclen);
uint8_t *encode64(uint8_t *dst, size_t dstlen, const uint8_t *src, size_t srclen);

#endif
