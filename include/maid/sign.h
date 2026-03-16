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

#ifndef MAID_SIGN_H
#define MAID_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct maid_sign maid_sign;

bool maid_sign_config(maid_sign *s, void *pub, void *prv);
bool maid_sign_generate(maid_sign *s, const uint8_t *data,
                        size_t size, uint8_t *sign);
bool maid_sign_verify(maid_sign *s, const uint8_t *data,
                      size_t size, const uint8_t *sign);

#endif
