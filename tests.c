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

static void print_yescrypt(const char *passwd, const char *salt,
    yescrypt_flags_t flags,
    uint64_t N, uint32_t r, uint32_t p, uint32_t t, uint32_t g,
    uint32_t dklen)
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
                puts("FAILED");
                return;
        }

        printf("yescrypt(\"%s\",\"%s\",%u,%llu,%u,%u,%u,%u) = ",
            passwd, salt, flags, (unsigned long long)N, r, p, t, g);

        if (yescrypt_kdf(NULL, &local,
            (const uint8_t *) passwd, strlen(passwd),
            (const uint8_t *) salt, strlen(salt), &params, dk, dklen)) {
                yescrypt_free_local(&local);
                puts(" FAILED");
                return;
        }

        yescrypt_free_local(&local);

        for (i = 0; i < dklen; i++)
                printf("%02x", dk[i]);
        puts("");
}

void test_crypt_gensalt_yescrypt(const char *prefix, unsigned long count)
{
	char entropy[256] = {0};
	char buf[256];
	char *ret;

	printf("- _crypt_gensalt_yescrypt_rn(count=%ld (N=%lu,r=%lu,t=%lu))\n",
	    count, count & 0x3f, (count >> 6) & 0x3f, (count >> 12) & 0x3);
	ret = _crypt_gensalt_yescrypt_rn(prefix, count, entropy, 5, buf, sizeof(buf));

	printf("  = %s", ret);
	if (ret == NULL) {
		printf(", errno = ");
		if (errno == EINVAL)
			printf("EINVAL");
		else if (errno == ERANGE)
			printf("ERANGE");
		else
			printf("%d", errno);
	}
	printf("\n");
}

int main(int argc, const char * const *argv)
{
        print_yescrypt("", "", 0, 16, 1, 1, 0, 0, 64);
        print_yescrypt("", "", 0, 16, 1, 1, 0, 0, 8);
        print_yescrypt("", "", 0, 4, 1, 1, 0, 0, 64);

#define NRT(n, r, t) ((n & 0x3f) | (r & 0x3f) << 6 | (t & 0x3) << 12)

	test_crypt_gensalt_yescrypt("$y$", NRT(0, 0, 0));
	test_crypt_gensalt_yescrypt("$y$", NRT(1, 0, 0));
	test_crypt_gensalt_yescrypt("$y$", NRT(2, 1, 0));
	test_crypt_gensalt_yescrypt("$y$", NRT(3, 2, 1));
	test_crypt_gensalt_yescrypt("$y$", NRT(46, 2, 1));
	test_crypt_gensalt_yescrypt("$y$", NRT(47, 2, 1));
	test_crypt_gensalt_yescrypt("$y$", NRT(48, 2, 1));
	test_crypt_gensalt_yescrypt("$y$", NRT(49, 2, 1));

}
