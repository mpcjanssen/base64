CFLAGS += -std=c89 -O3 -Wall -Wextra -pedantic

base64: main.c base64.c
	$(CC) $(CFLAGS) -o $@ $^

t: test.c
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -arch armv7 -arch armv7s -arch arm64 -pipe -no-cpp-precomp -isysroot /Applications/Xcode.app/Contents/Developer//Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.1.sdk -miphoneos-version-min=7.0 -g -O1 -I/Users/dmb/inky-core/python/local-install/ios/2.7/include/python2.7 test.c -o t -O3 -DUSE_FAST_B64_CODEC -DWITH_URLSAFE -DSKIP_INVALID -I../../auxlibs/src/base64

.PHONY: clean analyze

analyze: clean
	scan-build --use-analyzer=`which clang` --status-bugs make

clean:
	rm -f base64
