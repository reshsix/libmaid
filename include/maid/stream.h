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

#ifndef MAID_STREAM_H
#define MAID_STREAM_H

#include <maid/types.h>

struct maid_stream_def
{
    void * (*new)(const u8, const u8 *, const u8 *, const u64);
    void * (*del)(void *);
    void (*gen)(void *, u8 *);
    const size_t state_s;
    const u8 version;
};

typedef struct maid_stream maid_stream;
maid_stream *maid_stream_new(struct maid_stream_def def,
                             const u8 *restrict key,
                             const u8 *restrict nonce,
                             const u64 counter);
maid_stream *maid_stream_del(maid_stream *st);
void maid_stream_xor(maid_stream *st, u8 *buffer, size_t size);

/* Provided algorithms */

extern const struct maid_stream_def maid_chacha20;

#endif
