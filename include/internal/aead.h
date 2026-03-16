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

#ifndef INTERNAL_AEAD_H
#define INTERNAL_AEAD_H

#include <stdint.h>
#include <stdbool.h>

#include <maid/aead.h>
#include <maid/stream.h>

struct maid_aead_def
{
    bool   (*init)(void *, maid_stream **, maid_mac **);
    size_t (*size)(void);
    bool   (*config)(maid_stream *, maid_mac *,
                     const uint8_t *, const uint8_t *);

    void (*mode)(maid_stream *, uint8_t *, size_t);
    size_t state_s;
    bool s_bits, s_big;
};

maid_aead *maid_aead_init(void *buffer, size_t buffer_s,
                          const struct maid_aead_def *def);
size_t maid_aead_size(const struct maid_aead_def *def);

#endif
