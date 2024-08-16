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

#include <maid/utils.h>
#include <maid/crypto/chacha.h>

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

/* External functions */

struct maid_chacha
{
    u8 ks, ns, *key, *nonce;
    u64 counter;
};

extern void *
maid_chacha_del(void *ctx)
{
    if (ctx)
    {
        struct maid_chacha *ch = ctx;
        maid_mem_clear(ch->key, ch->ks);
        free(ch->key);
    }
    free(ctx);

    return NULL;
}

extern void *
maid_chacha_new(const u8 version, const u8 *restrict key,
                const u8 *restrict nonce, const u64 counter)
{
    struct maid_chacha *ret = calloc(1, sizeof(struct maid_chacha));

    if (ret)
    {
        switch (version)
        {
            case MAID_CHACHA20V1_128:
                ret->ks = 16;
                ret->ns = 8;
                break;

            case MAID_CHACHA20V1_256:
                ret->ks = 32;
                ret->ns = 8;
                break;

            case MAID_CHACHA20V2_128:
                ret->ks = 16;
                ret->ns = 12;
                break;

            case MAID_CHACHA20V2_256:
                ret->ks = 32;
                ret->ns = 12;
                break;

            default:
                ret = maid_chacha_del(ret);
                break;
        }
    }

    if (ret)
    {
        ret->key = malloc(ret->ks);
        if (ret->key)
            memcpy(ret->key, key, ret->ks);
        else
            ret = maid_chacha_del(ret);
    }

    if (ret)
    {
        ret->nonce = (u8*)nonce;
        ret->counter = counter;
    }

    return ret;
}

extern void
maid_chacha_gen(void *ctx, u8 *out)
{
    if (ctx && out)
    {
        struct maid_chacha *ch = ctx;

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
        memcpy(&(out[48]),      &ch->counter, cs);
        memcpy(&(out[48 + cs]), ch->nonce,    ch->ns);

        u32 tmp[64 / sizeof(u32)] = {0};
        memcpy(tmp, out, 64);

        for (u8 i = 0; i < 10; i++)
            doubleround(tmp);

        /* A second copy to not rely on alignment of out */
        u32 tmp2[64 / sizeof(u32)] = {0};
        memcpy(tmp2, out, 64);

        for (u8 i = 0; i < 64 / sizeof(u32); i++)
            tmp2[i] += tmp[i];
        memcpy(out, tmp2, 64);

        ch->counter++;
        maid_mem_clear(tmp, sizeof(tmp));
        maid_mem_clear(tmp2, sizeof(tmp2));
    }
}
