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

#ifndef MAID_AEAD_H
#define MAID_AEAD_H

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>

/* Internal interface */

struct maid_aead_def
{
    void (*init)(struct maid_stream_def, const u8 *, const u8 *,
                 maid_stream **, maid_mac **, bool);
    void (*mode)(maid_stream *, u8 *, size_t);

    struct maid_stream_def s_def;
    const struct maid_mac_def *m_def;

    bool s_bits, s_big;
};

/* External interface */

typedef struct maid_aead maid_aead;
maid_aead *maid_aead_new(struct maid_aead_def def,
                         const u8 *restrict key,
                         const u8 *restrict nonce);
maid_aead *maid_aead_del(maid_aead *ae);
void maid_aead_renew(maid_aead *ae, const u8 *restrict key,
                     const u8 *restrict nonce);
void maid_aead_update(maid_aead *ae, const u8 *buffer, size_t size);
void maid_aead_crypt(maid_aead *ae, u8 *buffer,
                     size_t size, bool decrypt);
void maid_aead_digest(maid_aead *ae, u8 *output);

/* External algorithms */

extern const struct maid_aead_def maid_aes_gcm_128;
extern const struct maid_aead_def maid_aes_gcm_192;
extern const struct maid_aead_def maid_aes_gcm_256;

extern const struct maid_aead_def maid_chacha20poly1305;

#endif
