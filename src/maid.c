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

struct c20p1305_state
{
    bool decrypt;

    const u8 *nonce;
    const struct maid_cb_read *data;
    const struct maid_cb_write *out;

    maid_chacha *ch;
    u8 keystream[64], step;
    u32 counter;
};

static size_t
c20p1305_codec(void *ctx, u8 *data, const size_t bytes)
{
    /* Called by poly1305_data, bytes will always be 16 */
    (void)bytes;

    struct c20p1305_state *st = ctx;
    size_t read = st->data->f(st->data->ctx, data, 16);
    if (read)
    {
        if (st->step == 0)
        {
            st->counter++;
            maid_chacha_keystream(st->ch, st->nonce, (u8*)&(st->counter),
                                  st->keystream);
        }

        u8 *keypart = &(st->keystream[st->step * 16]);
        for (u8 i = 0; i < read; i++)
            data[i] ^= keypart[i];

        st->out->f(st->out->ctx, data, 16);
        st->step = (st->step + 1) % 4;

        /* Simpler than temporary memory */
        if (st->decrypt)
            for (u8 i = 0; i < read; i++)
                data[i] ^= keypart[i];
    }

    return read;
}

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
        struct c20p1305_state st = {.decrypt = decrypt, .nonce = nonce,
                                    .data = data, .out = out, .ch = ch};
        struct maid_cb_read ct = {.f = c20p1305_codec, .ctx = &st};

        maid_chacha_keystream(ch, nonce, (u8*)&(st.counter), st.keystream);
        if (tag)
            maid_poly1305_mac(st.keystream, &ct, ad, tag);

        maid_mem_clear(st.keystream, sizeof(st.keystream));
    }

    maid_chacha_del(ch);

    return (ch);
}

struct aes_gcm_state
{
    bool decrypt;

    u8 h[16], nonce[16];
    const struct maid_cb_read *data;
    const struct maid_cb_write *out;

    maid_aes *aes;
    u8 counter[16];
};

static size_t
aes_gcm_codec(void *ctx, u8 *data, const size_t bytes)
{
    /* Called by gmac, bytes will always be 16 */
    (void)bytes;

    struct aes_gcm_state *st = ctx;
    size_t read = st->data->f(st->data->ctx, data, 16);
    if (read)
    {
        /* Increases counter (big endian order) */
        volatile u8 carry = 1;
        for (u8 i = 15; i < 16; i--)
        {
            volatile u16 sum = carry + st->counter[i];

            st->counter[i] = sum & 0xFF;
            carry = sum >> 8;

            sum = 0;
        }
        carry = 0;

        /* AES-CTR encryption/decryption */
        u8 tmp[16] = {0};
        memcpy(tmp, st->counter, sizeof(tmp));
        maid_aes_encrypt(st->aes, tmp);

        if (!(st->decrypt))
        {
            for (u8 i = 0; i < 16; i++)
                data[i] ^= tmp[i];
            st->out->f(st->out->ctx, data, 16);
        }
        else
        {
            for (u8 i = 0; i < 16; i++)
                tmp[i] ^= data[i];
            st->out->f(st->out->ctx, tmp, 16);
        }

        maid_mem_clear(tmp, sizeof(tmp));
    }

    return read;
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
        struct aes_gcm_state st = {.decrypt = decrypt,
                                   .data = data, .out = out, .aes = aes};

        /* H is encrypted zeros */
        maid_aes_encrypt(aes, st.h);

        /* Counter is nonce || 2^31 */
        memcpy(st.counter, nonce, 12);
        st.counter[15] = 0x1;

        /* Nonce is saved encrypted for ghash */
        memcpy(st.nonce, nonce, 12);
        st.nonce[15] = 0x1;
        maid_aes_encrypt(aes, st.nonce);

        /* Works both ways */
        struct maid_cb_read ct = {.f = aes_gcm_codec, .ctx = &st};
        maid_gmac_ghash(st.h, st.nonce, &ct, ad, tag);

        maid_mem_clear(st.h,       sizeof(st.h));
        maid_mem_clear(st.counter, sizeof(st.counter));
        maid_mem_clear(st.nonce,   sizeof(st.nonce));
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
