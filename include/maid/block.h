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

#ifndef MAID_BLOCK_H
#define MAID_BLOCK_H

#include <maid/types.h>

struct maid_block_def
{
    void * (*new)(const u8, const u8 *);
    void * (*del)(void *);
    void (*encrypt)(void *, u8 *);
    void (*decrypt)(void *, u8 *);
    const size_t state_s;
    const u8 version;
};

typedef struct maid_block maid_block;
maid_block *maid_block_new(struct maid_block_def def,
                           const u8 *restrict key,
                           const u8 *restrict iv);
maid_block *maid_block_del(maid_block *bl);
void maid_block_ecb(maid_block *bl, u8 *buffer, bool decrypt);
void maid_block_ctr(maid_block *bl, u8 *buffer, size_t size);

/* Provided algorithms */

extern const struct maid_block_def maid_aes_128;
extern const struct maid_block_def maid_aes_192;
extern const struct maid_block_def maid_aes_256;

#endif
