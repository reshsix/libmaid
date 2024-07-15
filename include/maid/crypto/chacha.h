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

#ifndef MAID_CRYPTO_CHACHA
#define MAID_CRYPTO_CHACHA

#include <maid/types.h>

typedef struct maid_chacha maid_chacha;

enum maid_chacha_v
{
    MAID_CHACHA20V1_128,
    MAID_CHACHA20V1_256,
    MAID_CHACHA20V2_128,
    MAID_CHACHA20V2_256
};

maid_chacha *maid_chacha_new(const enum maid_chacha_v version, const u8 *key);
maid_chacha *maid_chacha_del(maid_chacha *ch);
bool maid_chacha_keystream(maid_chacha *ch, const u8 *restrict nonce,
                           const u8 *restrict counter, u8 *restrict out);

#endif
