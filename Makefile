CC      = /home/ruanjiaming/work/stm32/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-gcc
CFLAGS  = -Wall -Wextra -O2 -I.

# 自动匹配所有 *_test.c 生成可执行文件
SRCS    = $(wildcard *_test.c)
TARGETS = $(SRCS:.c=)

all: $(TARGETS)

%: %.c common.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
