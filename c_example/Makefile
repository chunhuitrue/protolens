# 编译
# make
# 运行
# LD_LIBRARY_PATH=../target/debug/ ./smtp

CC=gcc
LDFLAGS=-L../target/debug/
LDLIBS=-lprotolens -lpcap

TARGETS=simple smtp simple_thread

all: $(TARGETS)

simple: simple.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

smtp: smtp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

simple_thread: simple_thread.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGETS)
