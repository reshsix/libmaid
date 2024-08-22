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

#ifndef MAID_CRYPTO_AES_H
#define MAID_CRYPTO_AES_H

#include <maid/block.h>
extern const struct maid_block_def maid_aes_128;
extern const struct maid_block_def maid_aes_192;
extern const struct maid_block_def maid_aes_256;

#include <maid/aead.h>
extern const struct maid_aead_def maid_aes_gcm_128;
extern const struct maid_aead_def maid_aes_gcm_192;
extern const struct maid_aead_def maid_aes_gcm_256;

#endif
