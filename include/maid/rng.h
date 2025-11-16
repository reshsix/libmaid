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

#ifndef MAID_RNG_H
#define MAID_RNG_H

#include <stdint.h>

typedef struct maid_rng maid_rng;

maid_rng *maid_chacha20_rng(const uint8_t *entropy);
maid_rng *maid_rng_del(maid_rng *g);

void maid_rng_renew(maid_rng *g, const uint8_t *entropy);
void maid_rng_generate(maid_rng *g, uint8_t *buffer, size_t size);

#endif
