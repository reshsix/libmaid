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

#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>
#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>
#include <maid/rng.h>

/* Chacha20 implementation */

static u32
rotl(u32 a, u8 n)
{
    return (a << n) | (a >> (32 - n));
}

static void
quarterround(u32 *x, u8 a, u8 b, u8 c, u8 d)
{
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
}

static void
doubleround(u32 *block)
{
    /* Column round */
    quarterround(block,  0,  4,  8, 12);
    quarterround(block,  1,  5,  9, 13);
    quarterround(block,  2,  6, 10, 14);
    quarterround(block,  3,  7, 11, 15);

    /* Diagonal round */
    quarterround(block,  0,  5, 10, 15);
    quarterround(block,  1,  6, 11, 12);
    quarterround(block,  2,  7,  8, 13);
    quarterround(block,  3,  4,  9, 14);
}

/* Maid stream definitions */

enum
{
    CHACHA20_128, CHACHA20_256, CHACHA20_IETF
};

struct chacha
{
    u8 ks, ns, *key, *nonce;
    u64 counter;
};

static void *
chacha_del(void *ctx)
{
    if (ctx)
    {
        struct chacha *ch = ctx;

        maid_mem_clear(ch->key, ch->ks);
        free(ch->key);

        maid_mem_clear(ch->nonce, ch->ns);
        free(ch->nonce);
    }
    free(ctx);

    return NULL;
}

static void *
chacha_new(u8 version, const u8 *restrict key,
           const u8 *restrict nonce, u64 counter)
{
    struct chacha *ret = calloc(1, sizeof(struct chacha));

    if (ret)
    {
        switch (version)
        {
            case CHACHA20_128:
                ret->ks = 16;
                ret->ns = 8;
                break;

            case CHACHA20_256:
                ret->ks = 32;
                ret->ns = 8;
                break;

            case CHACHA20_IETF:
                ret->ks = 32;
                ret->ns = 12;
                break;

            default:
                ret = chacha_del(ret);
                break;
        }
    }

    if (ret)
    {
        ret->key = calloc(1, ret->ks);
        ret->nonce = calloc(1, ret->ns);
        if (ret->key && ret->nonce)
        {
            memcpy(ret->key,     key, ret->ks);
            memcpy(ret->nonce, nonce, ret->ns);
            ret->counter = counter;
        }
        else
            ret = chacha_del(ret);
    }

    return ret;
}

static void
chacha_renew(void *ctx, const u8 *restrict key,
             const u8 *restrict nonce, u64 counter)
{
    if (ctx)
    {
        struct chacha *ch = ctx;

        if (key)
            memcpy(ch->key, key, ch->ks);
        if (nonce)
            memcpy(ch->nonce, nonce, ch->ns);
        ch->counter = counter;
    }
}

static void
chacha_generate(void *ctx, u8 *out)
{
    if (ctx && out)
    {
        struct chacha *ch = ctx;

        if (ch->ks == 32)
        {
            strcpy((char*)out, "expand 32-byte k");
            memcpy(&(out[16]), ch->key, 32);
        }
        else
        {
            strcpy((char*)out, "expand 16-byte k");
            memcpy(&(out[16]), ch->key, 16);
            memcpy(&(out[32]), ch->key, 16);
        }

        u8 cs = (sizeof(u32) * 4) - ch->ns;
        maid_mem_write(&(out[48]), 0, cs, false, ch->counter);
        memcpy(&(out[48 + cs]), ch->nonce, ch->ns);

        u32 tmp[16] = {0};
        for (u8 i = 0; i < 16; i++)
            tmp[i] = maid_mem_read(out, i, sizeof(u32), false);

        for (u8 i = 0; i < 10; i++)
            doubleround(tmp);

        for (u8 i = 0; i < 16; i++)
        {
            tmp[i] += maid_mem_read(out, i, sizeof(u32), false);
            maid_mem_write(out, i, sizeof(u32), false, tmp[i]);
        }

        ch->counter++;
        maid_mem_clear(tmp, sizeof(tmp));
    }
}

const struct maid_stream_def maid_chacha20 =
{
    .new      = chacha_new,
    .del      = chacha_del,
    .renew    = chacha_renew,
    .generate = chacha_generate,
    .state_s  = 64,
    .version  = CHACHA20_IETF
};

/* Maid AEAD definitions */

static void
chacha20poly1305_init(struct maid_stream_def def,
                      const u8 *key, const u8 *nonce,
                      maid_stream **st, maid_mac **m,
                      bool renew)
{
    if (!renew)
        *st = maid_stream_new(def, key, nonce, 0);
    else if (*st)
        maid_stream_renew(*st, key, nonce, 0);

    if (*st)
    {
        /* Poly1305 ephemeral key (32 bytes)
         * Uses a chacha block to increase the counter */
        u8 ekey[64] = {0};
        maid_stream_xor(*st, ekey, sizeof(ekey));

        if (!renew)
            *m = maid_mac_new(maid_poly1305, ekey);
        else if (*m)
            maid_mac_renew(*m, ekey);

        maid_mem_clear(ekey, sizeof(ekey));
    }
}

const struct maid_aead_def maid_chacha20poly1305 =
{
    .init  = chacha20poly1305_init,
    .mode  = maid_stream_xor,
    .s_def = maid_chacha20,

    .m_def  = &maid_poly1305,
    .s_big  = false,
    .s_bits = false,
};

/* Maid RNG definitions */

struct chacha20_rng
{
    maid_stream *st;
};

static void *
chacha20_rng_del(void *ctx)
{
    if (ctx)
    {
        struct chacha20_rng *chr = ctx;
        maid_stream_del(chr->st);
    }
    free(ctx);

    return NULL;
}

static void *
chacha20_rng_new(u8 version, const u8 *entropy)
{
    struct chacha20_rng *ret = calloc(1, sizeof(struct chacha20_rng));

    (void)version;
    if (ret)
    {
        ret->st = maid_stream_new(maid_chacha20, entropy, &(entropy[32]), 0);
        if (!(ret->st))
            ret = chacha20_rng_del(ret);
    }

    return ret;
}

static void
chacha20_rng_renew(void *ctx, const u8 *entropy)
{
    if (ctx)
    {
        struct chacha20_rng *ctr = ctx;
        maid_stream_renew(ctr->st, entropy, &(entropy[32]), 0);
    }
}

static void
chacha20_rng_generate(void *ctx, u8 *buffer)
{
    if (ctx && buffer)
    {
        struct chacha20_rng *ctr = ctx;
        memset(buffer, '\0', 64);
        maid_stream_xor(ctr->st, buffer, 64);
    }
}

const struct maid_rng_def maid_chacha20_rng =
{
    .new      = chacha20_rng_new,
    .del      = chacha20_rng_del,
    .renew    = chacha20_rng_renew,
    .generate = chacha20_rng_generate,
    .state_s  = 64,
    .version  = 0
};
