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

#ifndef INTERNAL_MAC_H
#define INTERNAL_MAC_H

#include <stdint.h>

struct maid_mac_def
{
    void * (*new)(const uint8_t *, uint8_t, uint8_t, uint8_t);
    void * (*del)(void *);
    void (*renew)(void *, const uint8_t *);
    void (*update)(void *, uint8_t *, size_t);
    void (*digest)(void *, uint8_t *);
};

maid_mac *maid_mac_new(const struct maid_mac_def *def, const uint8_t *key,
                       uint8_t key_s, uint8_t state_s, uint8_t digest_s);

#endif
