/*-
 * Copyright 2013-2018 Alexander Peslyak
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

static void test_gost2012_hash(char *m, size_t size, size_t bits, char *match)
{
	gost2012_hash_ctx ctx;
	int i;

	init_gost2012_hash_ctx(&ctx, bits);
	gost2012_hash_block(&ctx, (unsigned char *)m, size);
	uint8_t dg[bits / 8];
	gost2012_finish_hash(&ctx, dg);

	char dgt[bits / 4 + 1];
        for (i = 0; i < sizeof(dg); i++) {
                printf("%02x", dg[i]);
		sprintf(&dgt[i * 2], "%02x", dg[i]);
	}
        puts("");

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
	if (count)
		printf("[N=%lu,r=%lu,t=%lu]",
		    count & 0x3f, (count >> 6) & 0x3f, (count >> 12) & 0x3);

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
int main(int argc, const char * const *argv)
{
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

	test_crypt_gensalt_yescrypt("$y$", NRT(0, 0, 0), "$y$j9T$.......");

	test_yescrypt_match("pleaseletmein", "$7$C6..../....SodiumChloride",
	    "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D");
	test_yescrypt_match("pleaseletmein", "$7$06..../....SodiumChloride",
	    "$7$06..../....SodiumChloride$ENlyo6fGw4PCcDBOFepfSZjFUnVatHzCcW55.ZGz3B0");
	test_yescrypt_match("pleaseletmein", "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.",
	    "$y$jD5.7$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIugoNB6");

	/* test vector from example A.1 from GOST-34.11-2012 */
	test_gost2012_hash("012345678901234567890123456789012345678901234567890123456789012", 63,
	    512,
	    "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
	    "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
	test_gost2012_hash("012345678901234567890123456789012345678901234567890123456789012", 63,
	    256,
	    "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");

	return globerror;
}
