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

#ifndef MAID_FF_H
#define MAID_FF_H

#include <stdbool.h>

#include <maid/mp.h>

enum maid_ff_prime
{
    MAID_FF_1305, MAID_FF_25519, MAID_FF_ORDER25519
};

typedef struct maid_ff maid_ff;

maid_ff *maid_ff_new(enum maid_ff_prime prime);
maid_ff *maid_ff_del(struct maid_ff *ff);
maid_mp_word *maid_ff_prime(const maid_ff *ff);
void maid_ff_mod(size_t words, maid_mp_word *a, const maid_ff *ff);
void maid_ff_add(size_t words, maid_mp_word *a, const maid_mp_word *b,
                 const maid_ff *ff);
void maid_ff_sub(size_t words, maid_mp_word *a, const maid_mp_word *b,
                 const maid_ff *ff);
void maid_ff_mul(size_t words, maid_mp_word *a, const maid_mp_word *b,
                 const maid_ff *ff);
bool maid_ff_inv(size_t words, maid_mp_word *a, const maid_ff *ff);
void maid_ff_exp(size_t words, maid_mp_word *a, const maid_mp_word *b,
                 const maid_ff *ff);

#endif
