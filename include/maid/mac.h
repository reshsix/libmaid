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

/* Internal interface */

struct maid_mac_def
{
    void * (*new)(uint8_t, const uint8_t *);
    void * (*del)(void *);
    void (*renew)(void *, const uint8_t *);
    void (*update)(void *, uint8_t *, size_t);
    void (*digest)(void *, uint8_t *);
    size_t state_s;
    size_t digest_s;
    uint8_t version;
};

/* External interface */

typedef struct maid_mac maid_mac;
maid_mac *maid_mac_new(const struct maid_mac_def *def, const uint8_t *key);
maid_mac *maid_mac_del(maid_mac *m);
void maid_mac_renew(maid_mac *m, const uint8_t *key);
void maid_mac_update(maid_mac *m, const uint8_t *buffer, size_t size);
size_t maid_mac_digest(maid_mac *m, uint8_t *output);

/* External algorithms */

extern const struct maid_mac_def maid_poly1305;

extern const struct maid_mac_def maid_hmac_sha224;
extern const struct maid_mac_def maid_hmac_sha256;
extern const struct maid_mac_def maid_hmac_sha384;
extern const struct maid_mac_def maid_hmac_sha512;
extern const struct maid_mac_def maid_hmac_sha512_224;
extern const struct maid_mac_def maid_hmac_sha512_256;

struct maid_mac_def maid_blake2s_k(uint8_t digest_s);
struct maid_mac_def maid_blake2b_k(uint8_t digest_s);
extern const struct maid_mac_def maid_blake2s_128k;
extern const struct maid_mac_def maid_blake2s_160k;
extern const struct maid_mac_def maid_blake2s_224k;
extern const struct maid_mac_def maid_blake2s_256k;
extern const struct maid_mac_def maid_blake2b_160k;
extern const struct maid_mac_def maid_blake2b_256k;
extern const struct maid_mac_def maid_blake2b_384k;
extern const struct maid_mac_def maid_blake2b_512k;

#endif
