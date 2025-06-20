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

#ifndef MAID_SIGN_H
#define MAID_SIGN_H

#include <maid/types.h>

#include <maid/pub.h>

/* Internal interface */

struct maid_sign_def
{
    void * (*new)(u8, maid_pub *, maid_pub *, size_t);
    void * (*del)(void *);
    void (*renew)(void *, maid_pub *, maid_pub *);
    void (*generate)(void *, u8 *);
    bool (*verify)(void *, u8 *);
    u8 version;
};

/* External interface */

typedef struct maid_sign maid_sign;
maid_sign *maid_sign_new(struct maid_sign_def def, maid_pub *public,
                         maid_pub *private, size_t bits);
void maid_sign_renew(maid_sign *s, maid_pub *public, maid_pub *private);
maid_sign *maid_sign_del(maid_sign *s);
void maid_sign_generate(maid_sign *s, u8 *buffer);
bool maid_sign_verify(maid_sign *s, u8 *buffer);

/* External algorithms */

extern const struct maid_sign_def maid_pkcs1_v1_5_sha1;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha224;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha256;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha384;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha512;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha512_224;
extern const struct maid_sign_def maid_pkcs1_v1_5_sha512_256;

#endif
