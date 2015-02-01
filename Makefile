LIBTOOL = libtool
UNAME_S=$(shell uname -s)


CFLAGS += -O3 -Wall -Wextra -pedantic
SSSE3_CFLAGS = -mssse3
AVX2_CFLAGS = -mavx2
NEON_CFLAGS =
NEON64_CFLAGS =

OBJS = \
  base64.o \
  base64_avx2.o \
  base64_neon.o \
  base64_neon64.o \
  base64_ssse3.o \
  base64_std.o \
  cpufeatures.o

all: base64 libbase64.a

base64: main.o libbase64.a
	$(CC) $(LDFLAGS) -o $@ $^

libbase64.a: $(OBJS)
ifeq ($(UNAME_S),Darwin)
	$(LIBTOOL) -static $(OBJS) -o $@
else
	$(AR) -r $@ $(OBJS)
endif

base64_avx2.o: base64_avx2.c
	$(CC) $(CFLAGS) $(AVX2_CFLAGS) -o $@ -c $^

base64_neon.o: base64_neon.c
	$(CC) $(CFLAGS) $(NEON_CFLAGS) -o $@ -c $^

base64_neon64.o: base64_neon64.c
	$(CC) $(CFLAGS) $(NEON64_CFLAGS) -o $@ -c $^

base64_ssse3.o: base64_ssse3.c
	$(CC) $(CFLAGS) $(SSSE3_CFLAGS) -o $@ -c $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

.PHONY: clean analyze

analyze: clean
	scan-build --use-analyzer=`which clang` --status-bugs make

clean:
	rm -f base64 libbase64.a *.o
