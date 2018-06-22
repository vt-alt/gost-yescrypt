
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

CC = gcc  
LD = $(CC)
RM = rm -f
CFLAGS = -Wall -O2 -fomit-frame-pointer -DSKIP_MEMZERO
LDFLAGS = -s -lrt

PROJ = tests
OBJS_YESCRYPT = yescrypt-opt.o yescrypt-common.o sha256.o insecure_memzero.o
OBJS_CRYPT = crypt-yescrypt.o crypt-gostyescrypt.o
OBJS_GOST = gosthash2012.o
OBJS_TESTS = $(OBJS_YESCRYPT) $(OBJS_GOST) $(OBJS_CRYPT) tests.o
OBJS_RM = *.o

all: $(PROJ)

check: tests
	./tests

.c.o:
	$(CC) -c $(CFLAGS) $*.c

yescrypt-opt.o: yescrypt-platform.c
gosthash2012.o: gosthash2012.h gosthash2012_const.h gosthash2012_precalc.h\
	gosthash2012_ref.h gosthash2012_sse2.h

tests: $(OBJS_TESTS)
	$(LD) $(LDFLAGS) $(OBJS_TESTS) -o $@

clean:
	$(RM) $(PROJ) $(OBJS_TESTS) $(OBJS_RM)

.PHONY: all check tests clean
