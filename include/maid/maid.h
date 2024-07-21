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

#ifndef MAID_H
#define MAID_H

#include <maid/types.h>
#include <maid/utils.h>

enum maid_op
{
    MAID_ENCRYPT, MAID_DECRYPT
};

enum maid_cipher
{
    MAID_CHACHA20POLY1305
};

bool maid_crypt(enum maid_op op, enum maid_cipher cph,
                const u8 *key, const u8 *nonce,
                const struct maid_cb_read  *data,
                const struct maid_cb_read  *ad,
                const struct maid_cb_write *out,
                u8 *tag);

bool maid_crypt2(enum maid_op op, enum maid_cipher cph,
                 const u8 *key, const u8 *nonce,
                 const u8 *data, const size_t data_s,
                 const u8 *ad,   const size_t ad_s,
                       u8 *out,  const size_t out_s,
                 u8 *tag);

#endif
