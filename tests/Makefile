CC = gcc
CFLAGS = -Wall -Wextra -Werror -I../include
LDFLAGS = -lsodium

# Link against the actual project modules (excluding src/main.o)
MODULES = ../obj/common.o ../obj/terminal.o ../obj/crypto.o

all: test_runner

test_runner: test_core.c $(MODULES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	./$@

clean:
	rm -f test_runner *.o *.tmp

.PHONY: all clean
