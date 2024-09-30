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
    /* Amount of words */
    size_t words;
    /* Accumulator */
    maid_mp_word *acc;
    /* R and S key parts */
    maid_mp_word *r, *s;
    /* Temporary buffer */
    maid_mp_word *tmp;
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
        ((u32*)p->r)[0] &= 0x0FFFFFFF;
        ((u32*)p->r)[1] &= 0x0FFFFFFC;
        ((u32*)p->r)[2] &= 0x0FFFFFFC;
        ((u32*)p->r)[3] &= 0x0FFFFFFC;
    }
}

static void *
poly1305_del(void *ctx)
{
    if (ctx)
    {
        struct poly1305 *p = ctx;
        maid_mem_clear(p->acc,     p->words * sizeof(maid_mp_word));
        maid_mem_clear(p->r,       p->words * sizeof(maid_mp_word));
        maid_mem_clear(p->s,       p->words * sizeof(maid_mp_word));
        maid_mem_clear(p->tmp, 3 * p->words * sizeof(maid_mp_word));

        free(p->acc);
        free(p->r);
        free(p->s);
        free(p->tmp);

        maid_mem_clear(ctx, sizeof(struct poly1305));
    }
    free(ctx);

    return NULL;
}

static void *
poly1305_new(const u8 *key)
{
    struct poly1305 *ret = calloc(1, sizeof(struct poly1305));

    if (ret)
    {
        /* 320 bits, to handle multiplication */
        ret->words = maid_mp_words(320);

        ret->acc = calloc(ret->words,     sizeof(maid_mp_word));
        ret->r   = calloc(ret->words,     sizeof(maid_mp_word));
        ret->s   = calloc(ret->words,     sizeof(maid_mp_word));
        ret->tmp = calloc(ret->words * 3, sizeof(maid_mp_word));

        maid_mp_mov(ret->words, ret->acc, NULL);
        maid_mp_mov(ret->words, ret->r,   NULL);
        maid_mp_mov(ret->words, ret->s,   NULL);
        maid_mp_mov(ret->words, ret->tmp, NULL);

        if (key && ret->acc && ret->r && ret->s && ret->tmp)
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

        maid_mem_clear(p->acc,     p->words * sizeof(maid_mp_word));
        maid_mem_clear(p->tmp, 3 * p->words * sizeof(maid_mp_word));
    }
}

static void
poly1305_update(void *ctx, u8 *block, size_t size)
{
    /* 2^130 - 5 little endian */
    const u8 prime[80] =
        {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03};

    if (ctx && block)
    {
        struct poly1305 *p = ctx;

        maid_mp_word pr[10] = {0};
        maid_mp_read(p->words, pr, prime, false);

        /* Read data into buffer */
        maid_mp_mov(p->words, p->tmp, NULL);
        memcpy(p->tmp, block, size);

        /* Pad buffer accordingly */
        p->tmp[size / sizeof(maid_mp_word)] |=
            1ULL << ((size % sizeof(maid_mp_word)) * 8);

        /* Adds block to the accumulator */
        maid_mp_add(p->words, p->acc, p->tmp);
        /* Multiplies accumulator by r */
        maid_mp_mul(p->words, p->acc, p->r, p->tmp);
        /* Reduction by prime */
        maid_mp_mod(p->words, p->acc, pr, p->tmp);
    }
}

static void
poly1305_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct poly1305 *p = ctx;

        /* Adds s to the accumulator */
        maid_mp_add(p->words, p->acc, p->s);
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
