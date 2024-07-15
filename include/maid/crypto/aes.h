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

#ifndef MAID_CRYPTO_AES_H
#define MAID_CRYPTO_AES_H

#include <maid/types.h>

typedef struct maid_aes maid_aes;

enum maid_aes_v
{
    MAID_AES128, MAID_AES192, MAID_AES256
};

maid_aes *maid_aes_new(const enum maid_aes_v version, const u8 *key);
maid_aes *maid_aes_del(maid_aes *aes);
bool maid_aes_encrypt(maid_aes *aes, u8 *block);
bool maid_aes_decrypt(maid_aes *aes, u8 *block);

#endif
