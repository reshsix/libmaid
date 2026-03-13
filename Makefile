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

.PHONY: all debug clean test

TARGETS = libmaid.a
all: CFLAGS += -march=native -O3 -DNDEBUG=1
all: $(TARGETS)
debug: CFLAGS += -Og -ggdb3
debug: $(TARGETS)
clean:
	@rm -rf build
	@rm -f libmaid.a

FOLDERS = build build/crypto
$(FOLDERS):
	@mkdir -p $@

OBJS = crypto/chacha.o crypto/poly1305.o \
       crypto/hmac.o crypto/sha.o crypto/blake2.o \
	   crypto/hkdf.o crypto/ed25519.o crypto/x25519.o \
       mem.o mp.o ff.o stream.o mac.o aead.o rng.o hash.o kdf.o \
	   ecc.o sign.o kex.o test.o
OBJS := $(addprefix build/, $(OBJS))
build/%.o: src/%.c | $(FOLDERS)
	@printf '%s\n' "  CC      $(@:build/%=%)"
	@$(CC) $(CFLAGS) -fPIC -c $< -o $@

libmaid.a: $(OBJS) | build
	@printf '%s\n' "  AR      $@"
	@ar cr $@ $^
	@printf '%s\n' "  RANLIB  $@"
	@ranlib $@

test: test.c | build
	@$(CC) $(CFLAGS) $^ -o build/test -L. -lmaid
	@build/test
