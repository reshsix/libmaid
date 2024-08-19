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

enum
{
    MAID_CHACHA20_128,
    MAID_CHACHA20_256,
    MAID_CHACHA20_IETF,
};

void *maid_chacha_new(const u8 version, const u8 *restrict key,
                      const u8 *restrict nonce, const u64 counter);
void *maid_chacha_del(void *ctx);

void maid_chacha_gen(void *ctx, u8 *out);

#endif
