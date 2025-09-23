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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <maid/mp.h>
#include <maid/mem.h>
#include <maid/hash.h>

#include <maid/ecc.h>
#include <maid/sign.h>

static bool
import_mp(size_t words, maid_mp_word *output, const char *input)
{
    bool ret = false;

    u8 buf[strlen(input) / 2];
    ret = (maid_mem_import(MAID_BASE16L, buf, sizeof(buf),
                           input, strlen(input)) == strlen(input));
    if (ret)
        maid_mp_read(words, output, buf, true);

    return ret;
}

/* Curve448 curve definition */

struct maid_ecc_point
{
    maid_mp_word *x, *z;
};

struct curve448
{
    size_t words;
    maid_mp_word *p;
};

static void *
curve448_del(void *ctx)
{
    free(ctx);
    return NULL;
}

static void *
curve448_new(void)
{
    struct curve448 *ret = calloc(1, sizeof(struct curve448));

    if (ret)
    {
        ret->words = maid_mp_words(448);
        ret->p = calloc(ret->words, sizeof(maid_mp_word));
        if (!(ret->words && ret->p))
            ret = curve448_del(ret);
    }

    if (ret && !import_mp(ret->words, ret->p,
                          "ffffffffffffffffffffffffffffffff"
                          "fffffffffffffffffffffffeffffffff"
                          "ffffffffffffffffffffffffffffffff"
                          "ffffffffffffffff"))
        ret = curve448_del(ret);

    return ret;
}

static void *
curve448_free(void *ctx, struct maid_ecc_point *p)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    if (p)
    {
        if (p->x)
            maid_mp_mov(words, p->x, NULL);
        if (p->z)
            maid_mp_mov(words, p->z, NULL);

        free(p->x);
        free(p->z);
    }

    free(p);

    return NULL;
}

static void *
curve448_alloc(void *ctx)
{
    struct maid_ecc_point *ret = calloc(1, sizeof(struct maid_ecc_point));

    if (ret)
    {
        struct curve448 *c = ctx;
        size_t words = c->words;

        ret->x = calloc(words, sizeof(maid_mp_word));
        ret->z = calloc(words, sizeof(maid_mp_word));

        if (!(ret->x && ret->z))
            ret = curve448_free(ctx, ret);
    }

    return ret;
}

static void
curve448_base(void *ctx, struct maid_ecc_point *p)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    maid_mp_mov(words, p->x, NULL);
    maid_mp_mov(words, p->z, NULL);
    p->x[0] = 5;
    p->z[0] = 1;
}

static void
curve448_copy(void *ctx, struct maid_ecc_point *p,
                const struct maid_ecc_point *q)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    if (q)
    {
        maid_mp_mov(words, p->x, q->x);
        maid_mp_mov(words, p->z, q->z);
    }
    else
    {
        maid_mp_mov(words, p->x, NULL);
        p->x[0] = 1;
        maid_mp_mov(words, p->z, NULL);
    }
}

static bool
curve448_encode(void *ctx, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve448 *c = ctx;
    size_t words = c->words;
    MAID_ALLOC_MP(buf, 1)

    maid_mp_mov(words, buf, p->z);
    ret = maid_mp_invmod(words, buf, c->p);
    if (ret)
    {
        maid_mp_mulmod(words, buf, p->x, c->p);
        maid_mp_write(words, buf, buffer, false);
    }

    MAID_CLEAR_MP(buf)

    return ret;
}

static bool
curve448_decode(void *ctx, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve448 *c = ctx;
    size_t words = c->words;
    MAID_ALLOC_MP(buf, 1)

    maid_mp_read(c->words, buf, buffer, false);
    ret = (maid_mp_cmp(c->words, buf, c->p) > 0);
    if (ret)
    {
        maid_mp_mov(c->words, p->x, buf);
        maid_mp_mov(c->words, p->z, NULL);
        p->z[0] = 1;
    }

    MAID_CLEAR_MP(buf)

    return ret;
}

static bool
curve448_cmp(void *ctx, const struct maid_ecc_point *a,
                          const struct maid_ecc_point *b)
{
    volatile bool ret = true;

    struct curve448 *c = ctx;
    size_t words = c->words;

    MAID_ALLOC_MP(buf, 1)
    MAID_ALLOC_MP(buf2, 1)
    MAID_ALLOC_MP(zi, 1)
    MAID_ALLOC_MP(zi2, 1)

    /* Inverse Z calculation */
    maid_mp_mov(words, zi,  a->z);
    maid_mp_mov(words, zi2, b->z);
    ret &= maid_mp_invmod(words, zi,  c->p);
    ret &= maid_mp_invmod(words, zi2, c->p);

    /* X comparison */
    maid_mp_mov(words, buf,  a->x);
    maid_mp_mov(words, buf2, b->x);
    maid_mp_mulmod(words, buf,  zi,  c->p);
    maid_mp_mulmod(words, buf2, zi2, c->p);
    ret &= (maid_mp_cmp(words, buf, buf2) == 0);

    MAID_CLEAR_MP(buf)
    MAID_CLEAR_MP(buf2)
    MAID_CLEAR_MP(zi)
    MAID_CLEAR_MP(zi2)

    return ret;
}

static void
curve448_dbl(void *ctx, struct maid_ecc_point *a)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    MAID_ALLOC_MP(aa,  1)
    MAID_ALLOC_MP(bb,  1)
    MAID_ALLOC_MP(cc,  1)
    MAID_ALLOC_MP(buf, 1)

    /* AA = (X + Z)^2 */
    maid_mp_mov(words, buf, a->x);
    maid_mp_addmod(words, buf, a->z, c->p);
    maid_mp_mov(words, aa, buf);
    maid_mp_mulmod(words, aa, buf, c->p);

    /* BB = (X - Z)^2 */
    maid_mp_mov(words, buf, a->x);
    maid_mp_submod(words, buf, a->z, c->p);
    maid_mp_mov(words, bb, buf);
    maid_mp_mulmod(words, bb, buf, c->p);

    /* CC = AA - BB */
    maid_mp_mov(words, cc, aa);
    maid_mp_submod(words, cc, bb, c->p);

    /* x = AA * BB */
    maid_mp_mov(words, a->x, aa);
    maid_mp_mulmod(words, a->x, bb, c->p);

    /* z = ((39081 * CC) + AA) * CC */
    maid_mp_mov(words, a->z, NULL);
    a->z[0] = 39081;
    maid_mp_mulmod(words, a->z, cc, c->p);
    maid_mp_addmod(words, a->z, aa, c->p);
    maid_mp_mulmod(words, a->z, cc, c->p);

    MAID_CLEAR_MP(aa)
    MAID_CLEAR_MP(bb)
    MAID_CLEAR_MP(cc)
    MAID_CLEAR_MP(buf)
}

static void
curve448_add(void *ctx, struct maid_ecc_point *a,
               const struct maid_ecc_point *b)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    /* Differential addition, only works with the ladder */
    MAID_ALLOC_MP(ad,  1)
    MAID_ALLOC_MP(bc,  1)
    MAID_ALLOC_MP(buf, 1)

    /* AD = (X1 + Z1) * (X2 - Z2) */
    maid_mp_mov(words, ad, a->x);
    maid_mp_addmod(words, ad, a->z, c->p);
    maid_mp_mov(words, buf, b->x);
    maid_mp_submod(words, buf, b->z, c->p);
    maid_mp_mulmod(words, ad, buf, c->p);

    /* BC = (X1 - Z1) * (X2 + Z2) */
    maid_mp_mov(words, bc, a->x);
    maid_mp_submod(words, bc, a->z, c->p);
    maid_mp_mov(words, buf, b->x);
    maid_mp_addmod(words, buf, b->z, c->p);
    maid_mp_mulmod(words, bc, buf, c->p);

    /* x = (AD + BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_mp_addmod(words, buf, bc, c->p);
    maid_mp_mov(words, a->x, buf);
    maid_mp_mulmod(words, a->x, buf, c->p);

    /* z = 5 * (AD - BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_mp_submod(words, buf, bc, c->p);
    maid_mp_mov(words, a->z, NULL);
    a->z[0] = 5;
    maid_mp_mulmod(words, a->z, buf, c->p);
    maid_mp_mulmod(words, a->z, buf, c->p);

    MAID_CLEAR_MP(ad)
    MAID_CLEAR_MP(bc)
    MAID_CLEAR_MP(buf)
}

static size_t
curve448_size(void *ctx, size_t *key_s, size_t *point_s)
{
    struct curve448 *c = ctx;
    size_t words = c->words;

    if (key_s)
        *key_s = 56;
    if (point_s)
        *point_s = 56;

    return words;
}

static bool
curve448_keygen(void *ctx, u8 *data, maid_rng *g)
{
    (void)ctx;
    maid_rng_generate(g, data, 56);
    return true;
}

static bool
curve448_scalar(void *ctx, const u8 *data, maid_mp_word *s)
{
    bool ret = false;

    struct curve448 *c = ctx;

    u8 buffer[56] = {0};
    memcpy(buffer, data, 56);

    buffer[0]  &= 252;
    buffer[55] &= 128;

    maid_mp_read(c->words, s, buffer, false);
    maid_mem_clear(buffer, sizeof(buffer));

    return ret;
}

static void
curve448_debug(void *ctx, const char *name, const struct maid_ecc_point *a)
{
    struct curve448 *c = ctx;
    fprintf(stderr, "%s (curve448)\n", name);
    maid_mp_debug(c->words, "x", a->x);
    maid_mp_debug(c->words, "z", a->z);
}

const struct maid_ecc_def maid_curve448 =
{
    .new    = curve448_new,    .del    = curve448_del,
    .alloc  = curve448_alloc,  .free   = curve448_free,
    .base   = curve448_base,   .copy   = curve448_copy,
    .encode = curve448_encode, .decode = curve448_decode,
    .cmp    = curve448_cmp,    .dbl    = curve448_dbl,
    .add    = curve448_add,    .size   = curve448_size,
    .keygen = curve448_keygen, .scalar = curve448_scalar,
    .debug  = curve448_debug,
    .bits   = 448,
    .flags  = MAID_ECC_DIFF_ADD | MAID_ECC_NO_INF | MAID_ECC_LADDER_AD
};
