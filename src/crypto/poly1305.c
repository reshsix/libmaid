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

#include <maid/ff.h>
#include <maid/mp.h>
#include <maid/mem.h>
#include <maid/mac.h>

/* Maid MAC definition */

struct poly1305
{
    /* 256 bits, to handle multiplication */
    MAID_MP_SCALAR(acc, 256);
    MAID_MP_SCALAR(r, 256);
    MAID_MP_SCALAR(s, 256);

    maid_ff *ff;
};

static void
poly1305_init(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct poly1305 *p = ctx;
        size_t words = MAID_MP_WORDS(128);

        /* R and S initialization */
        maid_mp_read(words, p->r, key,        false);
        maid_mp_read(words, p->s, &(key[16]), false);

        /* R clamping */
        static const u8 clamp[16] = {0xff, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f,
                                     0xfc, 0xff, 0xff, 0x0f};
        maid_mp_word cl[words];
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
        maid_ff_del(p->ff);
        maid_mem_clear(p, sizeof(struct poly1305));
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
        ret->ff = maid_ff_new(MAID_FF_1305);
        if (ret->ff)
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

        maid_mem_clear(p->acc, MAID_MP_BYTES(MAID_MP_WORDS(256)));
    }
}

static void
poly1305_update(void *ctx, u8 *block, size_t size)
{
    if (ctx && block)
    {
        struct poly1305 *p = ctx;
        size_t words = MAID_MP_WORDS(256);

        /* Read data into buffer (256 bits) */
        u8 buf[32] = {0};
        memcpy(buf, block, size);

        /* Pad buffer accordingly */
        buf[size] |= 1;

        /* Read buffer as number */
        maid_mp_word tmp[words];
        maid_mp_read(words, tmp, buf, false);
        maid_mem_clear(buf, sizeof(buf));

        /* Adds block to the accumulator */
        maid_mp_add(words, p->acc, tmp);
        maid_mem_clear(tmp, sizeof(tmp));
        /* Multiplies accumulator by r */
        maid_mp_mul(words, p->acc, p->r);
        /* Reduction by prime */
        maid_ff_mod(words, p->acc, p->ff);
    }
}

static void
poly1305_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct poly1305 *p = ctx;

        /* Adds s to the accumulator */
        maid_mp_add(MAID_MP_WORDS(256), p->acc, p->s);
        /* Exports 128 bits */
        maid_mp_write(MAID_MP_WORDS(128), p->acc, output, false);
    }
}

const struct maid_mac_def maid_poly1305 =
{
    .new      = poly1305_new,
    .del      = poly1305_del,
    .renew    = poly1305_renew,
    .update   = poly1305_update,
    .digest   = poly1305_digest,
    .state_s  = 16,
    .digest_s = 16,
};
