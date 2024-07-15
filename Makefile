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

CFLAGS += -Iinclude -Wall -Wextra

.PHONY: all debug clean install uninstall

TARGETS = build/libmaid.a build/libmaid.so
all: CFLAGS += -O2 -DNDEBUG=1
all: $(TARGETS)
debug: CFLAGS += -Og -ggdb3
debug: $(TARGETS)
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

FOLDERS = build build/crypto
$(FOLDERS):
	mkdir -p $@

OBJS = utils.o crypto/aes.o crypto/chacha.o 
OBJS := $(addprefix build/, $(OBJS))
build/%.o: src/%.c | $(FOLDERS)
	$(CC) $(CFLAGS) -c $< -o $@

build/libmaid.a: $(OBJS) | build
	ar ruv $@ $^
	ranlib $@
build/libmaid.so: $(OBJS) | build
	$(CC) -shared -o $@ $^
