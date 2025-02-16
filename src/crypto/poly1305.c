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
};

static void
poly1305_init(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct poly1305 *p = ctx;
        size_t words = maid_mp_words(128);

        /* R and S initialization */
        maid_mp_read(words, p->r, key,        false);
        maid_mp_read(words, p->s, &(key[16]), false);

        /* R clamping */
        static const u8 clamp[16] = {0xff, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f};
        maid_mp_word cl[p->words];
        maid_mp_mov(words, cl, NULL);
        maid_mp_read(words, cl, clamp, false);
        maid_mp_and(words, p->r, cl);
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

        free(p->acc);
        free(p->r);
        free(p->s);

        maid_mem_clear(ctx, sizeof(struct poly1305));
    }
    free(ctx);

    return NULL;
}

static void *
poly1305_new(u8 version, const u8 *key)
{
    (void)version;

    struct poly1305 *ret = calloc(1, sizeof(struct poly1305));

    if (ret)
    {
        /* 256 bits, to handle multiplication */
        ret->words = maid_mp_words(256);

        ret->acc = calloc(ret->words,     sizeof(maid_mp_word));
        ret->r   = calloc(ret->words,     sizeof(maid_mp_word));
        ret->s   = calloc(ret->words,     sizeof(maid_mp_word));

        maid_mp_mov(ret->words, ret->acc, NULL);
        maid_mp_mov(ret->words, ret->r,   NULL);
        maid_mp_mov(ret->words, ret->s,   NULL);

        if (key && ret->acc && ret->r && ret->s)
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
    }
}

static void
poly1305_update(void *ctx, u8 *block, size_t size)
{
    /* 2^130 - 5 little endian (256 bits) */
    static const u8 prime[32] =
        {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03};

    if (ctx && block)
    {
        struct poly1305 *p = ctx;

        /* Read prime data as number */
        maid_mp_word pr[p->words];
        maid_mp_mov(p->words, pr, NULL);
        maid_mp_read(p->words, pr, prime, false);

        /* Read data into buffer (256 bits) */
        u8 buf[32] = {0};
        memcpy(buf, block, size);

        /* Pad buffer accordingly */
        buf[size] |= 1;

        /* Read buffer as number */
        maid_mp_word tmp[p->words];
        maid_mp_read(p->words, tmp, buf, false);
        maid_mem_clear(buf, sizeof(buf));

        /* Adds block to the accumulator */
        maid_mp_add(p->words, p->acc, tmp);
        maid_mem_clear(tmp, sizeof(tmp));
        /* Multiplies accumulator by r */
        maid_mp_mul(p->words, p->acc, p->r);
        /* Reduction by prime */
        maid_mp_mod(p->words, p->acc, pr);
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
        maid_mp_write(maid_mp_words(128), p->acc, output, false);
    }
}

const struct maid_mac_def maid_poly1305 =
{
    .new = poly1305_new,
    .del = poly1305_del,
    .renew = poly1305_renew,
    .update = poly1305_update,
    .digest = poly1305_digest,
    .state_s = 16,
    .digest_s = 16,
};
