LIBTOOL = libtool

CFLAGS += -std=c89 -O3 -Wall -Wextra -pedantic
SSSE3_CFLAGS = -mssse3
AVX2_CFLAGS = -mavx2
NEON_CFLAGS =
NEON64_CFLAGS =

all: base64 libbase64.a

base64: main.c base64.c base64_std.c base64_ssse3.c base64_avx2.c base64_neon.c base64_neon64.c features.c
	$(CC) $(CFLAGS) -o $@ $^

libbase64.a: main.c base64.c base64_std.c base64_ssse3.c base64_avx2.c base64_neon.c base64_neon64.c features.c
	$(CC) $(CFLAGS) -c base64.c
	$(CC) $(CFLAGS) -c base64_std.c
	$(CC) $(CFLAGS) $(SSSE3_CFLAGS) -c base64_ssse3.c
	$(CC) $(CFLAGS) $(AVX2_CFLAGS) -c base64_avx2.c
	$(CC) $(CFLAGS) $(NEON_CFLAGS) -c base64_neon.c
	$(CC) $(CFLAGS) $(NEON64_CFLAGS) -c base64_neon64.c
	$(CC) $(CFLAGS) -c features.c
	$(LIBTOOL) -static base64.o base64_std.o base64_ssse3.o base64_avx2.o base64_neon.o base64_neon64.o features.o -o libbase64.a

t: test.c
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -arch armv7 -arch armv7s -arch arm64 -pipe -no-cpp-precomp -isysroot /Applications/Xcode.app/Contents/Developer//Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.1.sdk -miphoneos-version-min=7.0 -g -O1 -I/Users/dmb/inky-core/python/local-install/ios/2.7/include/python2.7 test.c -o t -O3 -DUSE_FAST_B64_CODEC -DWITH_URLSAFE -DSKIP_INVALID -I../../auxlibs/src/base64

.PHONY: clean analyze

analyze: clean
	scan-build --use-analyzer=`which clang` --status-bugs make

clean:
	rm -f base64 libbase64.a *.o
