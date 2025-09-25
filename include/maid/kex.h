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

#ifndef MAID_KEX_H
#define MAID_KEX_H

#include <maid/types.h>

/* Internal interface */

struct maid_kex_def
{
    void * (*new)(void);
    void * (*del)(void *);
    bool (*pubgen)(void *, const u8 *, u8 *);
    bool (*secgen)(void *, const u8 *, const u8 *, u8 *);
};

/* External interface */

typedef struct maid_kex maid_kex;
maid_kex *maid_kex_new(struct maid_kex_def def);
maid_kex *maid_kex_del(maid_kex *x);
bool maid_kex_pubgen(maid_kex *x, const u8 *private, u8 *public);
bool maid_kex_secgen(maid_kex *x, const u8 *private,
                     const u8 *public, u8 *buffer);

/* External algorithms */

extern const struct maid_kex_def maid_x25519;

#endif
