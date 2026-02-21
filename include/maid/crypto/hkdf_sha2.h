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

#ifndef MAID_CRYPTO_HKDF_SHA2_H
#define MAID_CRYPTO_HKDF_SHA2_H

#include <maid/kdf.h>

maid_kdf *maid_hkdf_sha2(void *buffer,
                         bool bits64, u8 digest_s, size_t output_s);
size_t maid_hkdf_sha2_s(bool bits64, u8 digest_s, size_t output_s);

#endif
