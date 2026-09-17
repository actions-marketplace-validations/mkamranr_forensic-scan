CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
PREFIX  ?= /usr/local
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean install test

all: build/app

build/app: $(OBJECTS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: build/app
	./build/app --self-test
	sh scripts/integration.sh

install: build/app
	install -m 755 build/app $(PREFIX)/bin/app

clean:
	rm -rf build $(OBJECTS)
