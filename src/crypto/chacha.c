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
#include <maid/mac.h>

#include <internal/rng.h>
#include <internal/aead.h>
#include <internal/types.h>
#include <internal/stream.h>

#include <maid/crypto/chacha20.h>
#include <maid/crypto/poly1305.h>
#include <maid/crypto/chacha20rng.h>

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

struct chacha20
{
    u8 key[32], nonce[12];
    u64 counter;
};

static bool
chacha20_init(void *ctx)
{
    /* IETF version */
    (void)ctx;
    return true;
}

static size_t
chacha20_size(void)
{
    return sizeof(struct chacha20);
}

static void
chacha20_config(void *ctx, const u8 *key, const u8 *nonce, u64 counter)
{
    struct chacha20 *ch = ctx;
    memcpy(ch->key,     key, sizeof(ch->key));
    memcpy(ch->nonce, nonce, sizeof(ch->nonce));
    ch->counter = counter;
}

static void
chacha20_generate(void *ctx, u8 *out)
{
    if (ctx && out)
    {
        struct chacha20 *ch = ctx;

        strcpy((char*)out, "expand 32-byte k");
        memcpy(&(out[16]), ch->key, 32);

        u8 cs = (sizeof(u32) * 4) - sizeof(ch->nonce);
        maid_mem_write(&(out[48]), 0, cs, false, ch->counter);
        memcpy(&(out[48 + cs]), ch->nonce, sizeof(ch->nonce));

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

static const struct maid_stream_def chacha20_def =
{
    .init     = chacha20_init,
    .size     = chacha20_size,
    .config   = chacha20_config,
    .generate = chacha20_generate,
    .state_s  = 64,
};

extern maid_stream *
maid_chacha20(void *buffer)
{
    return maid_stream_init(buffer, maid_chacha20_s(), &chacha20_def);
}

extern size_t
maid_chacha20_s(void)
{
    return maid_stream_size(&chacha20_def);
}

/* Maid AEAD definitions */

static void
chacha20poly1305_init(const u8 *key, const u8 *nonce,
                      maid_stream **st, maid_mac **m,
                      bool renew)
{
    if (!renew)
    {
        *st = calloc(1, maid_chacha20_s());
        *m  = calloc(1, maid_poly1305_s());
    }

    if (*st && *m)
    {
        maid_chacha20(*st);
        maid_stream_config(*st, key, nonce, 0);

        /* Poly1305 ephemeral key (32 bytes)
         * Uses a chacha block to increase the counter */
        u8 ekey[64] = {0};
        maid_stream_xor(*st, ekey, sizeof(ekey));
        maid_poly1305(*m);
        maid_mac_config(*m, ekey);

        /* TODO may fail */

        maid_mem_clear(ekey, sizeof(ekey));
    }
}

static const struct maid_aead_def chacha20poly1305_def =
{
    .init  = chacha20poly1305_init,
    .mode  = maid_stream_xor,

    .state_s = 16,
    .s_big   = false,
    .s_bits  = false,
};

extern maid_aead *
maid_chacha20poly1305(const u8 *key, const u8 *nonce)
{
    return maid_aead_new(&chacha20poly1305_def, key, nonce);
}

/* Maid RNG definitions */

static bool
chacha20rng_init(void *buffer)
{
    return maid_chacha20(buffer);
}

static size_t
chacha20rng_size(void)
{
    return maid_chacha20_s();
}

static void
chacha20rng_config(void *ctx, const u8 *entropy)
{
    if (ctx && entropy)
        maid_stream_config(ctx, entropy, &(entropy[32]), 0);
}

static void
chacha20rng_generate(void *ctx, u8 *buffer)
{
    if (ctx && buffer)
        maid_stream_xor(ctx, buffer, 64);
}

static const struct maid_rng_def chacha20rng_def =
{
    .init     = chacha20rng_init,
    .size     = chacha20rng_size,
    .config   = chacha20rng_config,
    .generate = chacha20rng_generate,
    .state_s  = 64,
};

extern maid_rng *
maid_chacha20rng(void *buffer)
{
    return maid_rng_init(buffer, maid_chacha20rng_s(), &chacha20rng_def);
}

extern size_t
maid_chacha20rng_s(void)
{
    return maid_rng_size(&chacha20rng_def);
}
