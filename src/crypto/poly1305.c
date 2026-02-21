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
#include <maid/mac.h>
#include <maid/mem.h>

#include <internal/mp.h>
#include <internal/mac.h>
#include <internal/types.h>

#include <maid/crypto/poly1305.h>

/* Maid MAC definition */

struct poly1305
{
    /* 256 bits, to handle multiplication */
    MAID_MP_SCALAR(acc, 256);
    MAID_MP_SCALAR(r,   256);
    MAID_MP_SCALAR(s,   256);

    maid_ff *ff;
};

static void
poly1305_setup(void *ctx, const u8 *key)
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
poly1305_init(void *buffer, u8 key_s, u8 state_s, u8 digest_s)
{
    struct poly1305 *ret = buffer;

    (void)key_s;
    (void)state_s;
    (void)digest_s;

    ret->ff = maid_ff_init(&(ret[1]), MAID_FF_1305);
    if (!(ret->ff))
        ret = NULL;

    return ret;
}

static size_t
poly1305_size(u8 key_s, u8 state_s, u8 digest_s)
{
    (void)key_s;
    (void)state_s;
    (void)digest_s;

    return sizeof(struct poly1305) + maid_ff_size(MAID_FF_1305);
}

static void
poly1305_config(void *ctx, const u8 *key)
{
    if (ctx && key)
        poly1305_setup(ctx, key);
}

static void
poly1305_update(void *ctx, const u8 *block, size_t size)
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
        /* Clear accumulator */
        maid_mp_mov(MAID_MP_WORDS(256), p->acc, NULL);
    }
}

static const struct maid_mac_def poly1305_def =
{
    .init     = poly1305_init,
    .size     = poly1305_size,
    .config   = poly1305_config,
    .update   = poly1305_update,
    .digest   = poly1305_digest,
};

extern maid_mac *
maid_poly1305(void *buffer)
{
    return maid_mac_init(buffer, maid_poly1305_s(),
                         &poly1305_def, 32, 16, 16);
}

extern size_t
maid_poly1305_s(void)
{
    return maid_mac_size(&poly1305_def, 32, 16, 16);
}
