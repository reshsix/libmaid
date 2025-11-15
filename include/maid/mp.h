/*
 *  This file is part of libmaid
 *
 *  Libmaid is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  Libmaid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with libmaid; if not, see <https://www.gnu.org/licenses/>.
*/

#ifndef MAID_MP_H
#define MAID_MP_H

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t maid_mp_word;

void maid_mp_read(size_t words, maid_mp_word *a,
                  const uint8_t *addr, bool big);
void maid_mp_write(size_t words, const maid_mp_word *a,
                   uint8_t *addr, bool big);
void maid_mp_debug(size_t words, const char *name, const maid_mp_word *a);

void maid_mp_not(size_t words, maid_mp_word *a);
void maid_mp_and(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_orr(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_xor(size_t words, maid_mp_word *a, const maid_mp_word *b);

int8_t maid_mp_cmp(size_t words, const maid_mp_word *a, const maid_mp_word *b);

void maid_mp_mov(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_swap(size_t words, maid_mp_word *a, maid_mp_word *b, bool swap);

void maid_mp_shl(size_t words, maid_mp_word *a, uint64_t shift);
void maid_mp_shr(size_t words, maid_mp_word *a, uint64_t shift);
void maid_mp_sal(size_t words, maid_mp_word *a, uint64_t shift);
void maid_mp_sar(size_t words, maid_mp_word *a, uint64_t shift);

void maid_mp_add(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_sub(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_mul(size_t words, maid_mp_word *a, const maid_mp_word *b);

#endif
