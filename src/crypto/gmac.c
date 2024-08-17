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
#include <maid/types.h>

static void
gf128_mul(const u8 *a, const u8 *b, u8 *out)
{
    memset(out, '\0', 16);

    u8 tmp[16] = {0};
    memcpy(tmp, b, sizeof(tmp));

    volatile u8 value = 0x0;
    for (u8 i = 0; i < 128; i++)
    {
        u8 x = i / 8, y = i % 8;
        bool ai = (a[x] >> (7 - y)) & 0x1;
        for (u8 j = 0; j < 16; j++)
        {
            value = (ai) ? tmp[j] : 0x0;
            out[j] ^= value;
        }

        bool v0 = tmp[15] & 0x1;

        volatile u8 carry = 0;
        for (u8 j = 0; j < 16; j++)
        {
            value = tmp[j];
            tmp[j] >>= 1;
            tmp[j] |= (carry) ? 0x80 : 0x0;
            carry = value & 0x1;
        }
        carry = 0;

        value = (v0) ? 0xE1 : 0x0;
        tmp[0] ^= value;
    }
    value = 0x0;

    maid_mem_clear(tmp, 16);
}

struct maid_gmac
{
    u8 h[16], nonce[16];
    u8 acc[16], buffer[16];
};

extern void *
maid_gmac_del(void *ctx)
{
    if (ctx)
        maid_mem_clear(ctx, sizeof(struct maid_gmac));
    free(ctx);

    return NULL;
}

extern void *
maid_gmac_new(u8 *key)
{
    struct maid_gmac *ret = calloc(1, sizeof(struct maid_gmac));

    if (ret)
    {
        memcpy(ret->h,            key, sizeof(ret->h));
        memcpy(ret->nonce, &(key[16]), sizeof(ret->nonce));
    }

    return ret;
}

extern void
maid_gmac_update(void *ctx, u8 *block, size_t size)
{
    if (ctx && block)
    {
        struct maid_gmac *g = ctx;
        memcpy(g->buffer, block, size);
        memset(&(g->buffer[size]), 0, sizeof(g->buffer) - size);

        for (u8 i = 0; i < 16; i++)
            g->buffer[i] ^= g->acc[i];
        gf128_mul(g->buffer, g->h, g->acc);
    }
}

extern void
maid_gmac_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct maid_gmac *g = ctx;

        for (u8 i = 0; i < 16; i++)
            g->acc[i] ^= g->nonce[i];
        memcpy(output, g->acc, 16);
    }
}
