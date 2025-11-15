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

/* Internal interface */

struct maid_kdf_def
{
    void * (*new)(uint8_t, const void *, size_t);
    void * (*del)(void *);
    void (*renew)(void *, const void *);
    void (*hash)(void *, const uint8_t *, size_t,
                 const uint8_t *, size_t, uint8_t *);
    uint8_t version;
};

/* External interface */

typedef struct maid_kdf maid_kdf;
maid_kdf *maid_kdf_new(const struct maid_kdf_def *def,
                       const void *params, size_t output_s);
maid_kdf *maid_kdf_del(maid_kdf *k);
void maid_kdf_renew(maid_kdf *k, const void *params);
void maid_kdf_hash(struct maid_kdf *k, const uint8_t *data, size_t data_s,
                   const uint8_t *salt, size_t salt_s, uint8_t *output);

/* External algorithms */

#include <maid/mac.h>

struct maid_hkdf_params
{
    uint8_t *info;
    size_t info_s;
};

extern const struct maid_kdf_def maid_hkdf_sha224;
extern const struct maid_kdf_def maid_hkdf_sha256;
extern const struct maid_kdf_def maid_hkdf_sha384;
extern const struct maid_kdf_def maid_hkdf_sha512;
extern const struct maid_kdf_def maid_hkdf_sha512_224;
extern const struct maid_kdf_def maid_hkdf_sha512_256;

#endif
