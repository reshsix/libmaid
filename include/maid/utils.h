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

#ifndef MAID_UTILS_H
#define MAID_UTILS_H

#include <maid/types.h>

void maid_mem_clear(void *dest, const size_t length);

#ifndef NDEBUG
void maid_mp_debug(const char *name, const u32 *x, const size_t s);
#endif

void maid_mp_add(u32 *out, const u32 *a, const u32 *b,
                 const size_t so, const size_t sa, const size_t sb);
void maid_mp_sub(u32 *out, const u32 *a, const u32 *b,
                 const size_t so, const size_t sa, const size_t sb);
void maid_mp_mul(u32 *restrict out, const u32 *restrict a,
                 const u32 *restrict b, const size_t so,
                 const size_t sa, const size_t sb);
void maid_mp_shr(u32 *restrict out, const u32 *restrict a,
                 const size_t n, const size_t so, const size_t sa);

#endif
