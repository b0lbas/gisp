# root Makefile for gisp

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -Iinclude
LDFLAGS = -lsodium

SRC_DIR = src
OBJ_DIR = obj
BIN = gisp

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

PREFIX = /usr/local

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR) $(BIN)
	$(MAKE) -C tests clean

test: all
	$(MAKE) -C tests

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin($(BIN)

.PHONY: all clean test install uninstall
