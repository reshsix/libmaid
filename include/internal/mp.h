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

#ifndef INTERNAL_MP_H
#define INTERNAL_MP_H

#define MAID_MP_ALLOC(name, length) \
    maid_mp_word name[words * length]; \
    maid_mp_mov(words * length, name, NULL);
#define MAID_MP_CLEAR(name) \
    maid_mem_clear(name, sizeof(name));

#define MAID_MP_WORDS(bits) \
    (((bits) + (sizeof(maid_mp_word) * 8) - 1) / (sizeof(maid_mp_word) * 8))
#define MAID_MP_BITS(words) \
    (sizeof(maid_mp_word) * 8 * (words))
#define MAID_MP_BYTES(words) \
    (sizeof(maid_mp_word) * (words))
#define MAID_MP_SCALAR(name, bits) \
    maid_mp_word name[MAID_MP_WORDS(bits)]
#define MAID_MP_MAX \
    ((maid_mp_word)(-1))

#endif
