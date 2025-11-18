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

#ifndef INTERNAL_STREAM_H
#define INTERNAL_STREAM_H

#include <stdint.h>

struct maid_stream_def
{
    void * (*new)(const uint8_t *, const uint8_t *, const uint64_t);
    void * (*del)(void *);
    void (*renew)(void *, const uint8_t *, const uint8_t *, const uint64_t);
    void (*generate)(void *, uint8_t *);
    size_t state_s;
};

maid_stream *maid_stream_new(const struct maid_stream_def *def,
                             const uint8_t *key, const uint8_t *nonce,
                             uint64_t counter);

#endif
