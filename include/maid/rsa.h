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

#ifndef MAID_RSA_H
#define MAID_RSA_H

#include <maid/types.h>

#include <maid/mp.h>

typedef struct maid_rsa_public  maid_rsa_public;
typedef struct maid_rsa_private maid_rsa_private;

maid_rsa_public  *maid_rsa_new(const u8 *data, size_t size);
maid_rsa_private *maid_rsa_new2(const u8 *data, size_t size);
maid_rsa_public  *maid_rsa_del(maid_rsa_public *k);
maid_rsa_private *maid_rsa_del2(maid_rsa_private *k);

size_t maid_rsa_size(const maid_rsa_public *k);
size_t maid_rsa_size2(const maid_rsa_private *k);

u8 *maid_rsa_export(const maid_rsa_public *k, size_t *size);
u8 *maid_rsa_export2(const maid_rsa_private *k, size_t *size);

bool maid_rsa_encrypt(const maid_rsa_public *k,  maid_mp_word *s);
bool maid_rsa_decrypt(const maid_rsa_private *k, maid_mp_word *s);

maid_rsa_private *maid_rsa_keygen(size_t bits, u64 exponent, maid_rng *g);
maid_rsa_public  *maid_rsa_pubgen(maid_rsa_private *k);
bool maid_rsa_pair(maid_rsa_public *k, maid_rsa_private *k2);

#endif
