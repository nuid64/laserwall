TARGET := laserwall

CSRCS := $(wildcard src/*.c)

CC := clang
CFLAGS := -Wall -Wextra -O2
CINCLUDE := -Iinclude

$(TARGET): $(CSRCS)
	$(CC) $(CFLAGS) $(CINCLUDE) $^ -o $@
