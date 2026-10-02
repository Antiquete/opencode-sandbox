CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror

.PHONY: all test
all: build/opencode-guard

build/opencode-guard: sandbox/guard.c
	mkdir -p build
	$(CC) $(CFLAGS) -static -o $@ $<

test: all
	python3 -B -m unittest discover -s tests -v
