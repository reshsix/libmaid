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
    void * (*new)(uint8_t *, uint8_t *);
    void * (*del)(void *);
    size_t (*size)(void *);
    bool (*generate)(void *, const uint8_t *, size_t, uint8_t *);
    bool (*verify)(void *, const uint8_t *, size_t, const uint8_t *);
};

maid_sign *maid_sign_new(const struct maid_sign_def *def,
                         uint8_t *pub, uint8_t *prv);

#endif
