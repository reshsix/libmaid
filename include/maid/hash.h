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

#ifndef MAID_HASH_H
#define MAID_HASH_H

#include <stdint.h>

typedef struct maid_hash maid_hash;

maid_hash *maid_sha224(void);
maid_hash *maid_sha256(void);
maid_hash *maid_sha384(void);
maid_hash *maid_sha512(void);
maid_hash *maid_sha512_224(void);
maid_hash *maid_sha512_256(void);
maid_hash *maid_blake2s(uint8_t digest_s);
maid_hash *maid_blake2b(uint8_t digest_s);
maid_hash *maid_hash_del(maid_hash *h);

void maid_hash_renew(maid_hash *h);
void maid_hash_update(maid_hash *h, const uint8_t *buffer, size_t size);
size_t maid_hash_digest(maid_hash *h, uint8_t *output);

#endif
