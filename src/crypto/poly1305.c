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
#include <maid/mp.h>
#include <maid/mac.h>

/* Maid MAC definition */

struct poly1305
{
    /* 320 bits, to handle multiplication */
    u32 acc[10];
    /* R and S key parts */
    u32 r[10], s[10];
    /* Temporary buffer */
    u32 tmp[30];
};

static void
poly1305_init(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct poly1305 *p = ctx;

        /* R and S initialization */
        memcpy(p->r, key, 16);
        memcpy(p->s, &(key[16]), 16);

        /* R clamping */
        p->r[0] &= 0x0FFFFFFF;
        p->r[1] &= 0x0FFFFFFC;
        p->r[2] &= 0x0FFFFFFC;
        p->r[3] &= 0x0FFFFFFC;
    }
}

static void *
poly1305_del(void *ctx)
{
    if (ctx)
        maid_mem_clear(ctx, sizeof(struct poly1305));
    free(ctx);

    return NULL;
}

static void *
poly1305_new(const u8 *key)
{
    struct poly1305 *ret = calloc(1, sizeof(struct poly1305));

    if (ret)
    {
        if (key)
            poly1305_init(ret, key);
        else
            ret = poly1305_del(ret);
    }

    return ret;
}

static void
poly1305_renew(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct poly1305 *p = ctx;
        if (key)
            poly1305_init(p, key);

        maid_mem_clear(p->acc, sizeof(p->acc));
        maid_mem_clear(p->tmp, sizeof(p->tmp));
    }
}

static void
poly1305_update(void *ctx, u8 *block, size_t size)
{
    /* 2^130 - 5 little endian */
    const u32 prime[5] = {0xfffffffb, 0xffffffff,
                          0xffffffff, 0xffffffff, 0x3};

    u32 pr[10] = {0};
    for (size_t i = 0; i < 5; i++)
        maid_mem_write(pr, i, sizeof(u32), false, prime[i]);

    if (ctx && block)
    {
        struct poly1305 *p = ctx;

        /* Read data into buffer */
        memcpy(p->tmp, block, size);

        /* Pad buffer accordingly */
        if (sizeof(p->acc) > size)
            memset(&(((u8*)p->tmp)[size]), 0, sizeof(p->acc) - size);
        p->tmp[size / 4] |= 0x1 << ((size % 4) * 8);

        /* Adds block to the accumulator */
        maid_mp_add(10, p->acc, p->tmp);
        /* Multiplies accumulator by r */
        maid_mp_mul(10, p->acc, p->r, p->tmp);
        /* Reduction by prime */
        maid_mp_mod(10, p->acc, pr, p->tmp);
    }
}

static void
poly1305_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct poly1305 *p = ctx;

        /* Adds s to the accumulator */
        maid_mp_add(10, p->acc, p->s);
        /* Exports 128 bits */
        memcpy(output, p->acc, 16);
    }
}

const struct maid_mac_def maid_poly1305 =
{
    .new = poly1305_new,
    .del = poly1305_del,
    .renew = poly1305_renew,
    .update = poly1305_update,
    .digest = poly1305_digest,
    .state_s = 16
};
