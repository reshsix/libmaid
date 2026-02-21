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

#ifndef INTERNAL_KDF_H
#define INTERNAL_KDF_H

#include <stdint.h>

struct maid_kdf_def
{
    void * (*init)(void *, uint8_t, uint8_t, size_t);
    size_t (*size)(uint8_t, uint8_t, size_t);
    void (*config)(void *, const uint8_t *, size_t);
    void (*hash)(void *, const uint8_t *, size_t,
                 const uint8_t *, size_t, uint8_t *);
    uint8_t version;
};

struct maid_kdf *maid_kdf_init(void *buffer, size_t buffer_s,
                               const struct maid_kdf_def *def,
                               uint8_t state_s, uint8_t digest_s,
                               size_t output_s);
size_t maid_kdf_size(const struct maid_kdf_def *def,
                     uint8_t state_s, uint8_t digest_s, size_t output_s);

#endif
