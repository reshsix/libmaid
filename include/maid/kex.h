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
    void * (*new)(const void *, size_t);
    void * (*del)(void *);
    void (*renew)(void *, const void *);
    void (*gpub)(void *, const void *, void *);
    void (*gsec)(void *, const void *, const void *, u8 *);
    u8 version;
};

/* External interface */

typedef struct maid_kex maid_kex;
maid_kex *maid_kex_new(struct maid_kex_def def, const void *cfg, size_t bits);
void maid_kex_renew(maid_kex *x, const void *cfg);
maid_kex *maid_kex_del(maid_kex *x);
void maid_kex_gpub(maid_kex *x, const void *private, void *public);
void maid_kex_gsec(maid_kex *x, const void *private,
                   const void *public, u8 *buffer);

/* External algorithms */

#include <maid/mp.h>

struct maid_dh_group
{
    maid_mp_word *generator;
    maid_mp_word *modulo;
};

extern const struct maid_kex_def maid_dh;

#endif
