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

void maid_mp_debug(size_t words, const char *name, const u32 *a);

void maid_mp_read(size_t words, u32 *a, const u8 *addr, bool big);
void maid_mp_write(size_t words, const u32 *a, u8 *addr, bool big);

s8 maid_mp_cmp(size_t words, const u32 *a, const u32 *b);

void maid_mp_mov(size_t words, u32 *a, const u32 *b);

void maid_mp_add(size_t words, u32 *a, const u32 *b);
void maid_mp_sub(size_t words, u32 *a, const u32 *b);

void maid_mp_shl(size_t words, u32 *a, u64 shift);
void maid_mp_shr(size_t words, u32 *a, u64 shift);

void maid_mp_mul(size_t words, u32 *a, const u32 *b, u32 *tmp);
void maid_mp_div(size_t words, u32 *a, const u32 *b, u32 *tmp);
void maid_mp_mod(size_t words, u32 *a, const u32 *b, u32 *tmp);
void maid_mp_exp(size_t words, u32 *a, const u32 *b, u32 *tmp);

void maid_mp_div2(size_t words, u32 *a, u32 *rem, const u32 *b, u32 *tmp);
void maid_mp_egcd(size_t words, u32 *a, u32 *b, u32 *gcd, u32 *tmp);

void maid_mp_mulmod(size_t words, u32 *a, const u32 *b,
                    const u32 *mod, u32 *tmp);
void maid_mp_expmod(size_t words, u32 *a, const u32 *b,
                    const u32 *mod, u32 *tmp);

#endif
