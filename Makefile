#
#  This file is part of libmaid
#
#  Libmaid is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.
#
#  Libmaid is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with libmaid; if not, see <https://www.gnu.org/licenses/>.
#

CFLAGS += --std=c99 -Iinclude -Wall -Wextra

.PHONY: all debug clean install uninstall

TARGETS = build/libmaid.a build/libmaid.so
all: CFLAGS += -O2 -DNDEBUG=1
all: $(TARGETS)
debug: CFLAGS += -Og -ggdb3
debug: $(TARGETS) test
	gdb build/tests
clean:
	rm -rf build

DESTDIR ?= /usr/local
install: build/libmaid.a build/libmaid.so
	mkdir -p "$(DESTDIR)/lib"
	mkdir -p "$(DESTDIR)/include"
	cp build/libmaid.a  "$(DESTDIR)/lib/"
	cp build/libmaid.so "$(DESTDIR)/lib/"
	cp -r include/maid "$(DESTDIR)/include/"
uninstall:
	rm -rf "$(DESTDIR)/include/maid/"
	rm -rf "$(DESTDIR)/lib/libmaid.a"
	rm -rf "$(DESTDIR)/lib/libmaid.so"

test:
	$(CC) $(CFLAGS) tests.c -o build/tests -Lbuild -lmaid
	build/tests

FOLDERS = build build/crypto
$(FOLDERS):
	mkdir -p $@

OBJS = utils.o crypto/aes.o crypto/chacha.o \
               crypto/poly1305.o crypto/gcm.o \
               crypto/drbg.o crypto/sha2.o \
               mem.o block.o stream.o mac.o aead.o rng.o hash.o
OBJS := $(addprefix build/, $(OBJS))
build/%.o: src/%.c | $(FOLDERS)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

build/libmaid.a: $(OBJS) | build
	ar ruv $@ $^
	ranlib $@
build/libmaid.so: $(OBJS) | build
	$(CC) -shared -o $@ $^
