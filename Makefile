LIBTOOL = libtool

CFLAGS += -O3 -Wall -Wextra -pedantic
SSSE3_CFLAGS = -mssse3
AVX2_CFLAGS = -mavx2
NEON_CFLAGS =
NEON64_CFLAGS =

all: base64 libbase64.a

base64: main.c base64.c base64_std.c base64_ssse3.c base64_avx2.c base64_neon.c base64_neon64.c cpufeatures.c
	$(CC) $(CFLAGS) -o $@ $^

libbase64.a: main.c base64.c base64_std.c base64_ssse3.c base64_avx2.c base64_neon.c base64_neon64.c cpufeatures.c
	$(CC) $(CFLAGS) -c base64.c
	$(CC) $(CFLAGS) -c base64_std.c
	$(CC) $(CFLAGS) $(SSSE3_CFLAGS) -c base64_ssse3.c
	$(CC) $(CFLAGS) $(AVX2_CFLAGS) -c base64_avx2.c
	$(CC) $(CFLAGS) $(NEON_CFLAGS) -c base64_neon.c
	$(CC) $(CFLAGS) $(NEON64_CFLAGS) -c base64_neon64.c
	$(CC) $(CFLAGS) -c cpufeatures.c
	$(LIBTOOL) -static base64.o base64_std.o base64_ssse3.o base64_avx2.o base64_neon.o base64_neon64.o cpufeatures.o -o libbase64.a

.PHONY: clean analyze

analyze: clean
	scan-build --use-analyzer=`which clang` --status-bugs make

clean:
	rm -f base64 libbase64.a *.o
