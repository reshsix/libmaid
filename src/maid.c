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

#include <maid/maid.h>

static bool
c20p1305_crypt(bool decrypt, const u8 *key, const u8 *nonce,
               const struct maid_cb_read  *data,
               const struct maid_cb_read  *ad,
               const struct maid_cb_write *out,
               u8 *tag)
{
    maid_chacha *ch = maid_chacha_new(MAID_CHACHA20V2_256, key);

    if (ch)
    {
        /* Saves data in case of decryption */
        u8 cache[16] = {0};
        struct maid_cb_save sv = {.read = data,
                                  .buffer = cache, .buffer_s = 16};
        struct maid_cb_read rs = {.f = maid_cb_saver, .ctx = &sv};
        if (decrypt)
            data = &rs;

        /* Chacha20 encryption/decryption */
        u8 tmp[64] = {0};
        struct maid_stream st = {.read = data, .context = ch,
                                 .keystream = maid_chacha_keystream,
                                 .nonce = nonce, .counter = 1,
                                 .buffer = tmp, .buffer_s = sizeof(tmp)};
        struct maid_cb_read ct = {.f = maid_stream_xor, .ctx = &st};

        /* Outputs encrypt/decrypt data */
        struct maid_cb_split sp = {.read = &ct, .write = out};
        struct maid_cb_read ct2 = {.f = maid_cb_splitter, .ctx = &sp};
        struct maid_cb_read *last = &ct2;

        /* Loads cached data in case of decryption */
        struct maid_cb_load ld = {.read = &ct2, .saved = &sv};
        struct maid_cb_read rl = {.f = maid_cb_loader, .ctx = &ld};
        if (decrypt)
            last = &rl;

        /* Poly1305 ephemeral key */
        u8 tmp2[64] = {0};
        maid_chacha_keystream(ch, nonce, 0, tmp2);

        /* Endpoint function: swallows everything */
        maid_poly1305_mac(tmp2, last, ad, tag);

        /* Cleanup */
        if (decrypt)
            maid_mem_clear(cache, sizeof(cache));
        maid_mem_clear(tmp, sizeof(tmp));
        maid_mem_clear(tmp2, sizeof(tmp2));
    }

    maid_chacha_del(ch);

    return (ch);
}

static bool
aes_gcm_crypt(bool decrypt, const u8 *key, const u8 *nonce,
              const struct maid_cb_read  *data,
              const struct maid_cb_read  *ad,
              const struct maid_cb_write *out,
              u8 *tag)
{
    maid_aes *aes = maid_aes_new(MAID_AES256, key);

    if (aes)
    {
        /* Saves data in case of decryption */
        u8 cache[16] = {0};
        struct maid_cb_save sv = {.read = data,
                                  .buffer = cache, .buffer_s = 16};
        struct maid_cb_read rs = {.f = maid_cb_saver, .ctx = &sv};
        if (decrypt)
            data = &rs;

        /* AES encryption/decryption */
        u8 tmp[16] = {0};
        struct maid_block bt = {.read = data, .context = aes,
                                .encrypt = maid_aes_encrypt,
                                .decrypt = maid_aes_decrypt,
                                .nonce = nonce, .counter = 2,
                                .buffer = tmp, .buffer_s = sizeof(tmp)};
        struct maid_cb_read ct = {.f = maid_block_ctr, .ctx = &bt};

        /* Outputs encrypt/decrypt data */
        struct maid_cb_split sp = {.read = &ct, .write = out};
        struct maid_cb_read ct2 = {.f = maid_cb_splitter, .ctx = &sp};
        struct maid_cb_read *last = &ct2;

        /* Loads cached data in case of decryption */
        struct maid_cb_load ld = {.read = &ct2, .saved = &sv};
        struct maid_cb_read rl = {.f = maid_cb_loader, .ctx = &ld};
        if (decrypt)
            last = &rl;

        /* H is encrypted zeros */
        u8 h[16] = {0};
        maid_aes_encrypt(aes, h);

        /* Nonce is encrypted for ghash */
        u8 nonce2[16] = {0};
        memcpy(nonce2, nonce, 12);
        nonce2[15] = 0x1;
        maid_aes_encrypt(aes, nonce2);

        /* Endpoint function: swallows everything */
        maid_gmac_ghash(h, nonce2, last, ad, tag);

        /* Cleanup */
        if (decrypt)
            maid_mem_clear(cache, sizeof(cache));
        maid_mem_clear(tmp,    sizeof(tmp));
        maid_mem_clear(h,      sizeof(h));
        maid_mem_clear(nonce2, sizeof(nonce2));
    }

    maid_aes_del(aes);

    return (aes);
}

extern bool
maid_crypt(enum maid_op op, enum maid_cipher cph,
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
            case MAID_CHACHA20POLY1305:
                ret = c20p1305_crypt(op == MAID_DECRYPT,
                                     key, nonce, data, ad, out, tag);
                break;
            case MAID_AES_GCM:
                ret = aes_gcm_crypt(op == MAID_DECRYPT,
                                    key, nonce, data, ad, out, tag);
                break;
        }
    }

    return ret;
}

extern bool
maid_crypt2(enum maid_op op, enum maid_cipher cph,
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

    return maid_crypt(op, cph, key, nonce, &data_r, &ad_r, &out_w, tag);
}
