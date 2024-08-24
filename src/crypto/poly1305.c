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

#include <maid/mac.h>
#include <maid/utils.h>

/* Maid MAC definition */

struct poly1305
{
    /* 416 bits, to handle multiplication and reduction */
    u32 acc[13], acc2[13], acc3[13];
    /* R and S key parts */
    u32 r[4], s[4];
    /* Block buffer */
    u32 buffer[5];
};

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
        {
            /* R and S initialization */
            memcpy(ret->r, key, 16);
            memcpy(ret->s, &(key[16]), 16);

            /* R clamping */
            ret->r[0] &= 0x0FFFFFFF;
            ret->r[1] &= 0x0FFFFFFC;
            ret->r[2] &= 0x0FFFFFFC;
            ret->r[3] &= 0x0FFFFFFC;
        }
        else
            ret = poly1305_del(ret);
    }

    return ret;
}

static void
poly1305_update(void *ctx, u8 *block, size_t size)
{
    /* 2^130 - 5 little endian */
    const u32 prime[5] = {0xfffffffb, 0xffffffff,
                          0xffffffff, 0xffffffff, 0x3};
    /* 2^260 // prime, for Barret's reduction */
    const u32 m[5] = {0x00000005, 0x00000000,
                      0x00000000, 0x00000000, 0x4};
    if (ctx && block)
    {
        struct poly1305 *p = ctx;

        memcpy(p->buffer, block, size);
        if (sizeof(p->buffer) > size)
            memset(&(((u8*)p->buffer)[size]), 0, sizeof(p->buffer) - size);
        p->buffer[size / 4] |= 0x1 << ((size % 4) * 8);

        /* Adds block to the accumulator */
        maid_mp_add(p->acc2, p->acc, p->buffer, 13, 13, 5);

        /* Multiplies accumulator by r */
        maid_mp_mul(p->acc3, p->acc2, p->r, 13, 13, 4);

        /* Barret reduction by prime */
        maid_mp_mul(p->acc2, p->acc3,       m, 13, 13, 5);
        maid_mp_shr(p->acc,  p->acc2,     260, 13, 13);
        maid_mp_mul(p->acc2, p->acc,    prime, 13, 13, 5);
        maid_mp_sub(p->acc,  p->acc3, p->acc2, 13, 13, 13);
    }
}

static void
poly1305_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct poly1305 *p = ctx;

        /* Adds s to the accumulator */
        maid_mp_add(p->acc2, p->acc, p->s, 13, 13, 4);

        /* Exports 128 bits */
        memcpy(output, p->acc2, 16);
    }
}

const struct maid_mac_def maid_poly1305 =
{
    .new = poly1305_new,
    .del = poly1305_del,
    .update = poly1305_update,
    .digest = poly1305_digest,
    .state_s = 16
};