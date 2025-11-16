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

#ifndef MAID_AEAD_H
#define MAID_AEAD_H

#include <stdint.h>
#include <stdbool.h>

typedef struct maid_aead maid_aead;

maid_aead *maid_chacha20poly1305(const uint8_t *restrict key,
                                 const uint8_t *restrict nonce);
maid_aead *maid_aead_del(maid_aead *ae);

void maid_aead_renew(maid_aead *ae,
                     const uint8_t *restrict key,
                     const uint8_t *restrict nonce);
void maid_aead_update(maid_aead *ae, const uint8_t *buffer, size_t size);
void maid_aead_crypt(maid_aead *ae, uint8_t *buffer,
                     size_t size, bool decrypt);
void maid_aead_digest(maid_aead *ae, uint8_t *output);

#endif
