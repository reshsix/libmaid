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

#ifndef MAID_PUB_H
#define MAID_PUB_H

#include <maid/types.h>

/* Internal interface */

struct maid_pub_def
{
    void * (*new)(const struct maid_pub_def *, const void *, size_t);
    void * (*del)(void *);
    void (*renew)(void *, const void *);
    void (*apply)(void *, u8 *);
    const struct maid_pub_def *self;
};

/* External interface */

typedef struct maid_pub maid_pub;
maid_pub *maid_pub_new(struct maid_pub_def def, const void *key, size_t bits);
void maid_pub_renew(maid_pub *p, const void *key);
maid_pub *maid_pub_del(maid_pub *p);
const struct maid_pub_def *maid_pub_info(struct maid_pub *p, size_t *bits);
void maid_pub_apply(maid_pub *p, u8 *buffer);

/* External algorithms */

#include <maid/mp.h>

struct maid_rsa_key
{
    maid_mp_word *exponent;
    maid_mp_word *modulo;
};

extern const struct maid_pub_def maid_rsa_public;
extern const struct maid_pub_def maid_rsa_private;

#endif
