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

#ifndef MAID_MAC_H
#define MAID_MAC_H

#include <stdint.h>
#include <stdbool.h>

typedef struct maid_mac maid_mac;

maid_mac *maid_poly1305(const uint8_t *key);
maid_mac *maid_hmac_sha2(bool bits64, const uint8_t *key, uint8_t digest_s);
maid_mac *maid_blake2k(bool bits64, const uint8_t *key, uint8_t digest_s);
maid_mac *maid_mac_del(maid_mac *m);

void maid_mac_renew(maid_mac *m, const uint8_t *key);
void maid_mac_update(maid_mac *m, const uint8_t *buffer, size_t size);
size_t maid_mac_digest(maid_mac *m, uint8_t *output);

#endif
