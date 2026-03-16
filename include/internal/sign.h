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

#ifndef INTERNAL_SIGN_H
#define INTERNAL_SIGN_H

#include <stdint.h>
#include <stdbool.h>

struct maid_sign_def
{
    void * (*init)(void *);
    size_t (*size)(void);
    bool (*config)(void *, const void *, const void *);
    bool (*generate)(void *, const uint8_t *, size_t, uint8_t *);
    bool (*verify)(void *, const uint8_t *, size_t, const uint8_t *);
};

maid_sign *maid_sign_init(void *buffer, size_t buffer_s,
                          const struct maid_sign_def *def);
size_t maid_sign_size(const struct maid_sign_def *def);

#endif
