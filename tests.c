/*-
 * Copyright 2018 vt@altlinux.org
 * Based on work of (C) 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "sha256.h"
#include "yescrypt.h"
#include "crypt-yescrypt.h"
#include "gosthash2012.h"

static int globerror = 0;
#define RED	"\033[1;31m"
#define GREEN	"\033[1;32m"
#define NORM	"\033[m"

static void dumphex(const void *ptr, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		printf("%02x", ((unsigned char *)ptr)[i]);
}

static void test_gost2012_hash(char *m, size_t bits, char *match)
{
	gost2012_hash_ctx ctx;
	int i;
	size_t len = strlen(m);

	printf("m[%lu] = ", len);
	dumphex(m, len);
	puts("");
	init_gost2012_hash_ctx(&ctx, bits);
	gost2012_hash_block(&ctx, (unsigned char *)m, len);
	uint8_t dg[bits / 8];
	gost2012_finish_hash(&ctx, dg);

	printf("digest(%ld) = ", bits);
	dumphex(dg, sizeof(dg));
        puts("");

	char dgt[bits / 4 + 1];
	for (i = 0; i < sizeof(dg); i++)
		sprintf(&dgt[i * 2], "%02x", dg[i]);
	if (strcmp(dgt, match) != 0) {
		puts(RED "= BAD" NORM);
		globerror++;
	} else
		puts(GREEN "= GOOD" NORM);
}

static void test_yescrypt_kdf(const char *passwd, const char *salt,
    yescrypt_flags_t flags,
    uint64_t N, uint32_t r, uint32_t p, uint32_t t, uint32_t g,
    uint32_t dklen,
    uint8_t *match, uint32_t match_size)
{
        yescrypt_local_t local;
        yescrypt_params_t params = {flags, N, r, p, t, g};
        uint8_t dk[64];
        int i;

#if 1   
        /* Don't test hash upgrades */
        if (g)  
                return;
#endif  

        if (dklen > sizeof(dk) || yescrypt_init_local(&local)) {
                puts(RED "FAILED" NORM);
		globerror++;
                return;
        }

        printf("yescrypt(\"%s\",\"%s\",%u,%llu,%u,%u,%u,%u) = ",
            passwd, salt, flags, (unsigned long long)N, r, p, t, g);

        if (yescrypt_kdf(NULL, &local,
            (const uint8_t *) passwd, strlen(passwd),
            (const uint8_t *) salt, strlen(salt), &params, dk, dklen)) {
                yescrypt_free_local(&local);
                puts(RED " FAILED" NORM);
		globerror++;
                return;
        }

        yescrypt_free_local(&local);

        for (i = 0; i < dklen; i++)
                printf("%02x", dk[i]);
        puts("");

	if (dklen != match_size ||
	    memcmp(dk, match, dklen) != 0) {
		puts(RED "= BAD" NORM);
		globerror++;
	} else
		puts(GREEN "= GOOD" NORM);
}

static void test_crypt_gensalt_yescrypt(const char *prefix, unsigned long count, char *match)
{
	char entropy[256] = {0};
	char buf[256];
	char *retval;

	printf("_crypt_gensalt_yescrypt_rn(count=%ld)", count);

	retval = _crypt_gensalt_yescrypt_rn(prefix, count, entropy, 5, buf, sizeof(buf));

	printf(" = %s", retval);
	if (retval == NULL) {
		printf(", errno = ");
		if (errno == EINVAL)
			printf("EINVAL");
		else if (errno == ERANGE)
			printf("ERANGE");
		else
			printf("%d", errno);
	}
	printf("\n");
	if (!retval ||
	    strcmp(retval, match)) {
		puts(RED "= BAD" NORM);
		globerror++;
	} else
		puts(GREEN "= GOOD" NORM);
}

static void test_crypt_gensalt_gostyescrypt(const char *prefix, unsigned long count, char *match)
{
	char entropy[256] = {0};
	char buf[256];
	char *retval;

	printf("_crypt_gensalt_gostyescrypt_rn(count=%ld)", count);

	retval = _crypt_gensalt_gostyescrypt_rn(prefix, count, entropy, 5, buf, sizeof(buf));

	printf(" = %s", retval);
	if (retval == NULL) {
		printf(", errno = ");
		if (errno == EINVAL)
			printf("EINVAL");
		else if (errno == ERANGE)
			printf("ERANGE");
		else
			printf("%d", errno);
	}
	printf("\n");
	if (!retval ||
	    strcmp(retval, match)) {
		puts(RED "= BAD" NORM);
		globerror++;
	} else
		puts(GREEN "= GOOD" NORM);
}

static char *test_yescrypt(const char *passwd, const char *setting)
{
	static char bufs[256];
	char *retval;

	retval = _crypt_yescrypt_rn(passwd, setting, bufs, sizeof(bufs));
	printf("%s(%s) -> ", passwd, setting);
	if (retval)
		printf("%s", retval);
	else {
		if (errno == EINVAL)
			printf("EINVAL");
		else if (errno == ERANGE)
			printf("ERANGE");
		else
			printf("%d", errno);
	}
	printf("\n");

	return retval;
}

static char *test_gostyescrypt(const char *passwd, const char *setting)
{
	static char bufs[256];
	char *retval;

	retval = _crypt_gostyescrypt_rn(passwd, setting, bufs, sizeof(bufs));
	printf("%s(%s) -> ", passwd, setting);
	if (retval)
		printf("%s", retval);
	else {
		if (errno == EINVAL)
			printf("EINVAL");
		else if (errno == ERANGE)
			printf("ERANGE");
		else
			printf("%d", errno);
	}
	printf("\n");

	return retval;
}

static void test_yescrypt_match(const char *passwd, const char *setting, const char *match)
{
	char *retval = test_yescrypt(passwd, setting);
	if (retval && strcmp(match, retval) == 0)
		printf(GREEN "= GOOD\n" NORM);
	else {
		printf(RED "= BAD\n" NORM);
		globerror++;
	}
}

static void test_gostyescrypt_match(const char *passwd, const char *setting, const char *match)
{
	char *retval = test_gostyescrypt(passwd, setting);
	if (retval && strcmp(match, retval) == 0)
		printf(GREEN "= GOOD\n" NORM);
	else {
		printf(RED "= BAD\n" NORM);
		globerror++;
	}
}

void test_gost_hmac256(const char *k, size_t ksize, const char *t, size_t tlen, const char *match)
{
	uint8_t digest[32];

	printf("key: ");
	dumphex(k, ksize);
	printf("\nt:   ");
	dumphex(t, tlen);
	gost_hmac256((uint8_t *)k, ksize, (uint8_t *)t, tlen, digest);
	printf("\nhmac=");
	dumphex(digest, sizeof(digest));
	puts("");

	if (memcmp(digest, match, sizeof(digest))) {
		printf(RED "= BAD\n" NORM);
		globerror++;
	} else
		printf(GREEN "= GOOD\n" NORM);
}

int main(int argc, const char * const *argv)
{
	puts("TEST yescrypt_kdf");
	uint8_t t1[] = {
		0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
		0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
		0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
		0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
		0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
		0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
		0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
		0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
	};
	test_yescrypt_kdf("", "", 0, 16, 1, 1, 0, 0, 64, t1, sizeof(t1));

#define NRT(n, r, t) ((n & 0x3f) | (r & 0x3f) << 6 | (t & 0x3) << 12)

	puts("TEST crypt_gensalt_yescrypt");
	test_crypt_gensalt_yescrypt("$y$", 0, "$y$j9T$.......");

	puts("TEST crypt_yescrypt");
	test_yescrypt_match("pleaseletmein", "$7$C6..../....SodiumChloride",
	    "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D");
	test_yescrypt_match("pleaseletmein", "$7$06..../....SodiumChloride",
	    "$7$06..../....SodiumChloride$ENlyo6fGw4PCcDBOFepfSZjFUnVatHzCcW55.ZGz3B0");
	test_yescrypt_match("pleaseletmein", "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.",
	    "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6");

	puts("TEST gost2012_hash");
	/* test vector from example A.1 from GOST-34.11-2012 */
	test_gost2012_hash(
	    "012345678901234567890123456789012345678901234567890123456789012",
	    512,
	    "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
	    "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
	test_gost2012_hash(
	    "012345678901234567890123456789012345678901234567890123456789012",
	    256,
	    "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");

	/* test vector from example A.2 from GOST-34.11-2012 */
	test_gost2012_hash(
	    "\xD1\xE5\x20\xE2\xE5\xF2\xF0\xE8\x2C\x20\xD1\xF2\xF0\xE8\xE1\xEE"
	    "\xE6\xE8\x20\xE2\xED\xF3\xF6\xE8\x2C\x20\xE2\xE5\xFE\xF2\xFA\x20"
	    "\xF1\x20\xEC\xEE\xF0\xFF\x20\xF1\xF2\xF0\xE5\xEB\xE0\xEC\xE8\x20"
	    "\xED\xE0\x20\xF5\xF0\xE0\xE1\xF0\xFB\xFF\x20\xEF\xEB\xFA\xEA\xFB"
	    "\x20\xC8\xE3\xEE\xF0\xE5\xE2\xFB",
	    512,
	    "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376"
	    "035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28");
	test_gost2012_hash(
	    "\xD1\xE5\x20\xE2\xE5\xF2\xF0\xE8\x2C\x20\xD1\xF2\xF0\xE8\xE1\xEE"
	    "\xE6\xE8\x20\xE2\xED\xF3\xF6\xE8\x2C\x20\xE2\xE5\xFE\xF2\xFA\x20"
	    "\xF1\x20\xEC\xEE\xF0\xFF\x20\xF1\xF2\xF0\xE5\xEB\xE0\xEC\xE8\x20"
	    "\xED\xE0\x20\xF5\xF0\xE0\xE1\xF0\xFB\xFF\x20\xEF\xEB\xFA\xEA\xFB"
	    "\x20\xC8\xE3\xEE\xF0\xE5\xE2\xFB",
	    256,
	    "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50");

	/* carry test */
	test_gost2012_hash(
	    "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
	    "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
	    "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
	    "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
	    "\x16\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
	    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
	    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
	    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x16",
	    256,
	    "81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb");

	puts("TEST crypt_gensalt_gostyescrypt");
	test_crypt_gensalt_gostyescrypt("$gy$", 0, "$gy$j9T$.......");

	puts("TEST HMAC_GOSTR3411_2012_256");
	/* HMAC_GOSTR3411_2012_256 test vectors from P 50.1.113-2016 */
	test_gost_hmac256(
	    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32,
	    "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00", 16,
	    "\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
	    "\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9"
	    );

	puts("TEST crypt_gostyescrypt");
	test_gostyescrypt_match("pleaseletmein", "$gy$j9T$.......",
	    "$gy$j9T$.......$y3eHoiJIRW/bLU2rGdNkXdW1TnjArbeHgnZIwwv/lSC");
	test_gostyescrypt_match("pleaseletmeIn", "$gy$j9T$.......",
	    "$gy$j9T$.......$cNRMqOo1BZoPJWXL7mL/XFcsMy7fBAjii7zMCDc2zZ1");

	if (globerror)
		printf("%d failed tests\n", globerror);
	return globerror;
}
