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

/* Internal interface */

struct maid_sign_def
{
    void * (*new)(u8, void *, void *);
    void * (*del)(void *);
    size_t (*size)(void *);
    bool (*generate)(void *, const u8 *, size_t, u8 *);
    bool (*verify)(void *, const u8 *, size_t, const u8 *);
    u8 version;
};

/* External interface */

typedef struct maid_sign maid_sign;
maid_sign *maid_sign_new(struct maid_sign_def def, void *pub, void *priv);
maid_sign *maid_sign_del(maid_sign *s);
size_t maid_sign_size(maid_sign *s);
bool maid_sign_generate(maid_sign *s, const u8 *data, size_t size, u8 *sign);
bool maid_sign_verify(maid_sign *s,
                      const u8 *data, size_t size, const u8 *sign);

/* External algorithms */

extern const struct maid_sign_def maid_ed25519;

#endif
