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

maid_ecc *maid_curve25519(void);
maid_ecc *maid_edwards25519(void);
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

#endif
