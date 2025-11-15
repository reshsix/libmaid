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

#ifndef MAID_ECC_H
#define MAID_ECC_H

#include <stdint.h>
#include <stdbool.h>

#include <maid/mp.h>
#include <maid/rng.h>

typedef struct maid_ecc maid_ecc;
typedef struct maid_ecc_point maid_ecc_point;

/* Internal interface */

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

/* External interface */

maid_ecc *maid_ecc_new(const struct maid_ecc_def *def);
maid_ecc *maid_ecc_del(maid_ecc *c);

maid_ecc_point *maid_ecc_alloc(maid_ecc *c);
maid_ecc_point *maid_ecc_free(maid_ecc *c, maid_ecc_point *p);

void maid_ecc_base(maid_ecc *c, maid_ecc_point *p);
void maid_ecc_copy(maid_ecc *c, maid_ecc_point *p, const maid_ecc_point *q);
void maid_ecc_swap(maid_ecc *c, maid_ecc_point *p,
                   maid_ecc_point *q, bool swap);

bool maid_ecc_encode(maid_ecc *c, uint8_t *buffer, const maid_ecc_point *p);
bool maid_ecc_decode(maid_ecc *c, const uint8_t *buffer, maid_ecc_point *p);

bool maid_ecc_cmp(maid_ecc *c, const maid_ecc_point *p,
                               const maid_ecc_point *q);
void maid_ecc_dbl(maid_ecc *c, maid_ecc_point *p);
void maid_ecc_add(maid_ecc *c, maid_ecc_point *p, const maid_ecc_point *q);
void maid_ecc_mul(maid_ecc *c, maid_ecc_point *p,
                  const maid_mp_word *s);

size_t maid_ecc_size(maid_ecc *c, size_t *key_s, size_t *point_s);
uint8_t maid_ecc_flags(maid_ecc *c);

bool maid_ecc_keygen(maid_ecc *c, uint8_t *private, maid_rng *g);
bool maid_ecc_pubgen(maid_ecc *c, const uint8_t *private, uint8_t *public);
bool maid_ecc_scalar(maid_ecc *c, const uint8_t *private, maid_mp_word *s);

void maid_ecc_debug(maid_ecc *c, const char *name, const maid_ecc_point *a);

/* External algorithms */

extern const struct maid_ecc_def maid_curve25519;
extern const struct maid_ecc_def maid_edwards25519;

#endif
