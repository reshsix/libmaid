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

#ifndef MAID_MAC_H
#define MAID_MAC_H

#include <maid/types.h>

/* Internal interface */

struct maid_mac_def
{
    void * (*new)(const u8 *);
    void * (*del)(void *);
    void (*update)(void *, u8 *, size_t);
    void (*digest)(void *, u8 *);
    size_t state_s;
};

/* Internal algorithms */

extern const struct maid_mac_def maid_gcm;

/* External interface */

typedef struct maid_mac maid_mac;
maid_mac *maid_mac_new(struct maid_mac_def def, const u8 *key);
maid_mac *maid_mac_del(maid_mac *m);
void maid_mac_update(maid_mac *m, const u8 *buffer, size_t size);
void maid_mac_digest(maid_mac *m, u8 *output);

/* External algorithms */

extern const struct maid_mac_def maid_poly1305;

#endif
