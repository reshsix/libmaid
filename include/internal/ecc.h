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

#ifndef INTERNAL_ECC_H
#define INTERNAL_ECC_H

#include <stdint.h>
#include <stdbool.h>

#include <maid/mp.h>
#include <maid/rng.h>

enum
{
    MAID_ECC_DIFF_ADD  = 1,
    MAID_ECC_NO_INF    = 2,
    MAID_ECC_LADDER_AD = 4,
    MAID_ECC_NO_CLAMP  = 8,
};

struct maid_ecc_def
{
    void * (*new)(void);
    void * (*del)(void *);

    void * (*alloc)(void *);
    void * (*free)(void *, maid_ecc_point *);

    void (*base)(void *, maid_ecc_point *);
    void (*copy)(void *, maid_ecc_point *, const maid_ecc_point *);
    void (*swap)(void *, maid_ecc_point *, maid_ecc_point *, bool);

    bool (*encode)(void *, uint8_t *, const maid_ecc_point *);
    bool (*decode)(void *, const uint8_t *, maid_ecc_point *);

    bool (*cmp)(void *, const maid_ecc_point *, const maid_ecc_point *);
    void (*dbl)(void *, maid_ecc_point *);
    void (*add)(void *, maid_ecc_point *, const maid_ecc_point *);
    void (*add2)(void *, maid_ecc_point *,
                 const maid_ecc_point *, const maid_ecc_point *);

    size_t (*size)(void *, size_t *, size_t *);
    bool (*keygen)(void *, uint8_t *, maid_rng *);
    bool (*scalar)(void *, const uint8_t *, maid_mp_word *);

    void (*debug)(void *, const char *, const maid_ecc_point *);

    size_t bits;
    uint8_t flags;
};

struct maid_ecc *maid_ecc_new(const struct maid_ecc_def *def);

#endif
