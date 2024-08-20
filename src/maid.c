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

#include <string.h>

#include <maid/types.h>
#include <maid/utils.h>

#include <maid/crypto/chacha.h>
#include <maid/crypto/poly1305.h>

#include <maid/crypto/aes.h>
#include <maid/crypto/gmac.h>

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>

#include <maid/maid.h>

static bool
c20p1305_crypt(bool decrypt, const u8 *key, const u8 *nonce,
               const struct maid_cb_read  *data,
               const struct maid_cb_read  *ad,
               const struct maid_cb_write *out,
               u8 *tag)
{
    bool ret = false;

    maid_stream *st = maid_stream_new(maid_chacha20_ietf, key, nonce, 0);
    if (st)
    {
        /* Poly1305 ephemeral key (32 bytes)
         * Uses a chacha block to increase the counter */
        u8 key[64] = {0};
        maid_stream_xor(st, key, sizeof(key));

        maid_mac *m = maid_mac_new(maid_poly1305, key);
        if (m)
        {
            u8 block[16] = {0};

            u64 ad_s = 0;
            while (true)
            {
                u8 last = ad->f(ad->ctx, block, sizeof(block));
                if (last == 0)
                    break;

                if (last < sizeof(block))
                    memset(&(block[last]), '\0', sizeof(block) - last);
                maid_mac_update(m, block, sizeof(block));
                ad_s += last;
            }

            u64 ct_s = 0;
            while (true)
            {
                u8 last = data->f(data->ctx, block, sizeof(block));
                if (last == 0)
                    break;

                if (last < sizeof(block))
                    memset(&(block[last]), '\0', sizeof(block) - last);
                if (!decrypt)
                {
                    maid_stream_xor(st, block, last);
                    maid_mac_update(m, block, sizeof(block));
                }
                else
                {
                    maid_mac_update(m, block, sizeof(block));
                    maid_stream_xor(st, block, last);
                }
                out->f(out->ctx, block, last);
                ct_s += last;
            }

            memcpy(block,       &(ad_s), sizeof(ad_s));
            memcpy(&(block[8]), &(ct_s), sizeof(ct_s));
            maid_mac_update(m, block, sizeof(block));
            maid_mac_digest(m, tag);

            maid_mem_clear(block, sizeof(block));

            ret = true;
        }
        maid_mac_del(m);

        maid_mem_clear(key, sizeof(key));
    }
    maid_stream_del(st);

    return ret;
}

static bool
aes_gcm_crypt(struct maid_block_def aes, bool decrypt,
              const u8 *key, const u8 *nonce,
              const struct maid_cb_read  *data,
              const struct maid_cb_read  *ad,
              const struct maid_cb_write *out,
              u8 *tag)
{
    bool ret = false;

    u8 iv[16] = {0};
    memcpy(iv, nonce, 12);
    iv[15] = 0x1;

    maid_block *bl = maid_block_new(aes, key, iv);
    if (bl)
    {
        /* GMAC H and encrypted IV */
        u8 key[32] = {0};
        maid_block_ecb(bl, key, false);
        maid_block_ctr(bl, &(key[16]), sizeof(key) - 16);

        maid_mac *m = maid_mac_new(maid_gmac, key);
        if (m)
        {
            u8 block[16] = {0};

            u64 ad_s = 0;
            while (true)
            {
                u8 last = ad->f(ad->ctx, block, sizeof(block));
                if (last == 0)
                    break;

                if (last < sizeof(block))
                    memset(&(block[last]), '\0', sizeof(block) - last);
                maid_mac_update(m, block, sizeof(block));
                ad_s += last;
            }

            u64 ct_s = 0;
            while (true)
            {
                u8 last = data->f(data->ctx, block, sizeof(block));
                if (last == 0)
                    break;

                if (last < sizeof(block))
                    memset(&(block[last]), '\0', sizeof(block) - last);
                if (!decrypt)
                {
                    maid_block_ctr(bl, block, last);
                    maid_mac_update(m, block, sizeof(block));
                }
                else
                {
                    maid_mac_update(m, block, sizeof(block));
                    maid_block_ctr(bl, block, last);
                }
                out->f(out->ctx, block, last);
                ct_s += last;
            }
            ad_s *= 8;
            ct_s *= 8;

            /* Copies as big endian */
            for (u8 i = 0; i < 8; i++)
            {
                block[7  - i] = ((u8*)&ad_s)[i];
                block[15 - i] = ((u8*)&ct_s)[i];
            }
            maid_mac_update(m, block, sizeof(block));
            maid_mac_digest(m, tag);

            maid_mem_clear(block, sizeof(block));

            ret = true;
        }
        maid_mac_del(m);

        maid_mem_clear(key, sizeof(key));
    }
    maid_block_del(bl);

    return ret;
}

extern bool
maid_crypt_cb(enum maid_op op, enum maid_cipher cph,
              const u8 *key, const u8 *nonce,
              const struct maid_cb_read  *data,
              const struct maid_cb_read  *ad,
              const struct maid_cb_write *out,
              u8 *tag)
{
    bool ret = (op == MAID_ENCRYPT || op == MAID_DECRYPT) &&
               key && nonce && data && ad && out && tag;

    if (ret)
    {
        switch (cph)
        {
            case MAID_AES_128_GCM:
                ret = aes_gcm_crypt(maid_aes_128, op == MAID_DECRYPT,
                                    key, nonce, data, ad, out, tag);
                break;
            case MAID_AES_256_GCM:
                ret = aes_gcm_crypt(maid_aes_256, op == MAID_DECRYPT,
                                    key, nonce, data, ad, out, tag);
                break;
            case MAID_CHACHA20_POLY1305:
                ret = c20p1305_crypt(op == MAID_DECRYPT,
                                     key, nonce, data, ad, out, tag);
                break;
        }
    }

    return ret;
}

extern bool
maid_crypt(enum maid_op op, enum maid_cipher cph,
           const u8 *key, const u8 *nonce,
           const u8 *data, const size_t data_s,
           const u8 *ad,   const size_t ad_s,
                 u8 *out,  const size_t out_s,
           u8 *tag)
{
    struct maid_cb_buf data_b = {.data = (u8*)data, .limit = data_s};
    struct maid_cb_buf ad_b   = {.data = (u8*)ad,   .limit = ad_s};
    struct maid_cb_buf out_b  = {.data =      out,  .limit = out_s,
                                 .write = true};

    struct maid_cb_read  data_r = {.f = maid_cb_buffer, .ctx = &data_b};
    struct maid_cb_read  ad_r   = {.f = maid_cb_buffer, .ctx = &ad_b};
    struct maid_cb_write out_w  = {.f = maid_cb_buffer, .ctx = &out_b};

    return maid_crypt_cb(op, cph, key, nonce, &data_r, &ad_r, &out_w, tag);
}
