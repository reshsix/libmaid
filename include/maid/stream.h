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

#include <stdint.h>

typedef struct maid_stream maid_stream;

maid_stream *maid_chacha20(const uint8_t *key, const uint8_t *nonce,
                           uint64_t counter);
maid_stream *maid_stream_del(maid_stream *st);

void maid_stream_renew(maid_stream *st, const uint8_t *key,
                       const uint8_t *nonce, uint64_t counter);
void maid_stream_xor(maid_stream *st, uint8_t *buffer, size_t size);

#endif
