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

#include <maid/types.h>

typedef u64 maid_mp_word;

size_t maid_mp_words(size_t bits);

void maid_mp_read(size_t words, maid_mp_word *a, const u8 *addr, bool big);
void maid_mp_write(size_t words, const maid_mp_word *a, u8 *addr, bool big);

void maid_mp_debug(size_t words, const char *name, const maid_mp_word *a);

void maid_mp_not(size_t words, maid_mp_word *a);
void maid_mp_and(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_orr(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_xor(size_t words, maid_mp_word *a, const maid_mp_word *b);

s8 maid_mp_cmp(size_t words, const maid_mp_word *a, const maid_mp_word *b);

void maid_mp_mov(size_t words, maid_mp_word *a, const maid_mp_word *b);

void maid_mp_add(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_sub(size_t words, maid_mp_word *a, const maid_mp_word *b);

void maid_mp_shl(size_t words, maid_mp_word *a, u64 shift);
void maid_mp_shr(size_t words, maid_mp_word *a, u64 shift);

void maid_mp_sal(size_t words, maid_mp_word *a, u64 shift);
void maid_mp_sar(size_t words, maid_mp_word *a, u64 shift);

void maid_mp_mul(size_t words, maid_mp_word *a,
                 const maid_mp_word *b, maid_mp_word *tmp);
void maid_mp_div(size_t words, maid_mp_word *a,
                 const maid_mp_word *b, maid_mp_word *tmp);
void maid_mp_mod(size_t words, maid_mp_word *a,
                 const maid_mp_word *b, maid_mp_word *tmp);
void maid_mp_exp(size_t words, maid_mp_word *a,
                 const maid_mp_word *b, maid_mp_word *tmp);

void maid_mp_div2(size_t words, maid_mp_word *a, maid_mp_word *rem,
                  const maid_mp_word *b, maid_mp_word *tmp);

void maid_mp_mulmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_word *mod, maid_mp_word *tmp);
void maid_mp_expmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_word *mod, maid_mp_word *tmp,
                    bool constant);
bool maid_mp_invmod(size_t words, maid_mp_word *a,
                    const maid_mp_word *mod, maid_mp_word *tmp);
void maid_mp_expmod2(size_t words, maid_mp_word *a, const maid_mp_word *b,
                     const maid_mp_word *mod, maid_mp_word *tmp,
                     bool constant);

#include <maid/rng.h>
void maid_mp_random(size_t words, maid_mp_word *a, maid_rng *g, size_t bits);
void maid_mp_random2(size_t words, maid_mp_word *a, maid_rng *g,
                     const maid_mp_word *low, const maid_mp_word *high,
                     maid_mp_word *tmp);
void maid_mp_prime(size_t words, maid_mp_word *a, maid_rng *g,
                   size_t bits, size_t safety, maid_mp_word *tmp);

#endif
