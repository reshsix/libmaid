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

#include <stdint.h>
#include <stdbool.h>

/* Internal interface */

struct maid_kex_def
{
    void * (*new)(void);
    void * (*del)(void *);
    bool (*pubgen)(void *, const uint8_t *, uint8_t *);
    bool (*secgen)(void *, const uint8_t *, const uint8_t *, uint8_t *);
};

/* External interface */

typedef struct maid_kex maid_kex;
maid_kex *maid_kex_new(const struct maid_kex_def *def);
maid_kex *maid_kex_del(maid_kex *x);
bool maid_kex_pubgen(maid_kex *x, const uint8_t *private, uint8_t *public);
bool maid_kex_secgen(maid_kex *x, const uint8_t *private,
                     const uint8_t *public, uint8_t *buffer);

/* External algorithms */

extern const struct maid_kex_def maid_x25519;

#endif
