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

#ifndef MAID_SPKI_H
#define MAID_SPKI_H

#include <maid/types.h>

enum maid_spki
{
    MAID_SPKI_UNKNOWN,
    MAID_SPKI_RSA,
    MAID_SPKI_ED25519,
};

enum maid_spki maid_spki_import(const u8 *data, size_t size,
                                u8 **stream, size_t *length);
bool maid_spki_export(enum maid_spki type, const u8 *data, size_t size,
                                           u8 **stream, size_t *length);

#endif
