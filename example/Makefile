# LD_LIBRARY_PATH=target/debug/ ./c-example
CC=gcc
# CFLAGS=--std=c11
LDFLAGS=-L../target/debug/
LDLIBS=-lprotolens -lpcap

all: c-example

c-example: ffi.c
	$(CC) $(CFLAGS) -o c-example ffi.c $(LDFLAGS) $(LDLIBS)

clean:
	rm -f c-example
