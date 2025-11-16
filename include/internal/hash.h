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

#ifndef INTERNAL_HASH_H
#define INTERNAL_HASH_H

#include <stdint.h>

struct maid_hash_def
{
    void * (*new)(uint8_t);
    void * (*del)(void *);
    void (*renew)(void *);
    void (*update)(void *, uint8_t *, size_t);
    void (*digest)(void *, uint8_t *);
    size_t state_s;
    size_t digest_s;
    uint8_t version;
};

maid_hash *maid_hash_new(const struct maid_hash_def *def);

#endif
