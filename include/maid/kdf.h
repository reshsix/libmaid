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

#ifndef MAID_KDF_H
#define MAID_KDF_H

#include <stdint.h>
#include <stdbool.h>

typedef struct maid_kdf maid_kdf;

struct maid_hkdf_params
{
    uint8_t *info;
    size_t info_s;
};

maid_kdf *maid_hkdf_sha2(const struct maid_hkdf_params *p,
                         bool bits64, uint8_t digest_s, size_t output_s);
maid_kdf *maid_kdf_del(maid_kdf *k);

void maid_kdf_renew(maid_kdf *k, const void *params);
void maid_kdf_hash(struct maid_kdf *k, const uint8_t *data, size_t data_s,
                   const uint8_t *salt, size_t salt_s, uint8_t *output);


#endif
