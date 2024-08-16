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

#ifndef MAID_CRYPTO_GMAC
#define MAID_CRYPTO_GMAC

#include <maid/utils.h>
#include <maid/types.h>

void *maid_gmac_new(const u8 *key);
void *maid_gmac_del(void *ctx);
void maid_gmac_update(void *ctx, u8 *block, size_t size);
void maid_gmac_digest(void *ctx, u8 *output);

#endif
