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

/* Internal macros */

#define MAID_ALLOC_MP(name, length) \
    maid_mp_word name[words * length]; \
    maid_mp_mov(words * length, name, NULL);

#define MAID_CLEAR_MP(name) \
    maid_mem_clear(name, sizeof(name));

/* External functions */

typedef uint_fast16_t maid_mp_word;

#define MAID_MP_WORDS(bits) \
    (((bits) + (sizeof(maid_mp_word) * 8) - 1) / (sizeof(maid_mp_word) * 8))
#define MAID_MP_SCALAR(name, bits) \
    maid_mp_word name[MAID_MP_WORDS(bits)]
#define MAID_MP_BYTES(bits) \
    (MAID_MP_WORDS(bits) * sizeof(maid_mp_word))

void maid_mp_read(size_t words, maid_mp_word *a, const u8 *addr, bool big);
void maid_mp_write(size_t words, const maid_mp_word *a, u8 *addr, bool big);

void maid_mp_debug(size_t words, const char *name, const maid_mp_word *a);

void maid_mp_not(size_t words, maid_mp_word *a);
void maid_mp_and(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_orr(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_xor(size_t words, maid_mp_word *a, const maid_mp_word *b);

s8 maid_mp_cmp(size_t words, const maid_mp_word *a, const maid_mp_word *b);

void maid_mp_mov(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_swap(size_t words, maid_mp_word *a, maid_mp_word *b, bool swap);

void maid_mp_shl(size_t words, maid_mp_word *a, u64 shift);
void maid_mp_shr(size_t words, maid_mp_word *a, u64 shift);
void maid_mp_sal(size_t words, maid_mp_word *a, u64 shift);
void maid_mp_sar(size_t words, maid_mp_word *a, u64 shift);

void maid_mp_add(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_sub(size_t words, maid_mp_word *a, const maid_mp_word *b);
void maid_mp_mul(size_t words, maid_mp_word *a, const maid_mp_word *b);

typedef struct maid_mp_mod maid_mp_mod;
maid_mp_mod *maid_mp_mersenne(size_t words, size_t k,
                              maid_mp_word c, bool minus);
maid_mp_mod *maid_mp_mersenne2(size_t words, size_t k,
                               const maid_mp_word *c, bool minus);
maid_mp_word *maid_mp_fullmod(const maid_mp_mod *mod);
void maid_mp_redmod(size_t words, maid_mp_word *a, const maid_mp_mod *mod);
void maid_mp_addmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_mod *mod);
void maid_mp_submod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_mod *mod);
void maid_mp_mulmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_mod *mod);
bool maid_mp_invmod(size_t words, maid_mp_word *a, const maid_mp_mod *mod);
void maid_mp_expmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
                    const maid_mp_mod *mod);

#endif
