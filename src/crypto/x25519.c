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
#include <maid/kex.h>

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

/* Curve25519 curve definition */

struct maid_ecc_point
{
    maid_mp_word *x, *z;
};

struct curve25519
{
    size_t words;
    maid_mp_word *p;
};

static void *
curve25519_del(void *ctx)
{
    free(ctx);
    return NULL;
}

static void *
curve25519_new(void)
{
    struct curve25519 *ret = calloc(1, sizeof(struct curve25519));

    if (ret)
    {
        ret->words = maid_mp_words(256);
        ret->p = calloc(ret->words, sizeof(maid_mp_word));
        if (!(ret->words && ret->p))
            ret = curve25519_del(ret);
    }

    if (ret && !import_mp(ret->words, ret->p,
                          "7fffffffffffffffffffffffffffffff"
                          "ffffffffffffffffffffffffffffffed"))
        ret = curve25519_del(ret);

    return ret;
}

static void *
curve25519_free(void *ctx, struct maid_ecc_point *p)
{
    struct curve25519 *c = ctx;
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
curve25519_alloc(void *ctx)
{
    struct maid_ecc_point *ret = calloc(1, sizeof(struct maid_ecc_point));

    if (ret)
    {
        struct curve25519 *c = ctx;
        size_t words = c->words;

        ret->x = calloc(words, sizeof(maid_mp_word));
        ret->z = calloc(words, sizeof(maid_mp_word));

        if (!(ret->x && ret->z))
            ret = curve25519_free(ctx, ret);
    }

    return ret;
}

static void
curve25519_base(void *ctx, struct maid_ecc_point *p)
{
    struct curve25519 *c = ctx;
    size_t words = c->words;

    maid_mp_mov(words, p->x, NULL);
    maid_mp_mov(words, p->z, NULL);
    p->x[0] = 9;
    p->z[0] = 1;
}

static void
curve25519_copy(void *ctx, struct maid_ecc_point *p,
                const struct maid_ecc_point *q)
{
    struct curve25519 *c = ctx;
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
curve25519_encode(void *ctx, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve25519 *c = ctx;
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
curve25519_decode(void *ctx, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve25519 *c = ctx;
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
curve25519_cmp(void *ctx, const struct maid_ecc_point *a,
                          const struct maid_ecc_point *b)
{
    volatile bool ret = true;

    struct curve25519 *c = ctx;
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
curve25519_dbl(void *ctx, struct maid_ecc_point *a)
{
    struct curve25519 *c = ctx;
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

    /* z = ((121666 * CC) + BB) * CC */
    maid_mp_mov(words, a->z, NULL);
    a->z[0] = 121666;
    maid_mp_mulmod(words, a->z, cc, c->p);
    maid_mp_addmod(words, a->z, bb, c->p);
    maid_mp_mulmod(words, a->z, cc, c->p);

    MAID_CLEAR_MP(aa)
    MAID_CLEAR_MP(bb)
    MAID_CLEAR_MP(cc)
    MAID_CLEAR_MP(buf)
}

static void
curve25519_add2(void *ctx, struct maid_ecc_point *a,
                const struct maid_ecc_point *b,
                const struct maid_ecc_point *o)
{
    struct curve25519 *c = ctx;
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

    /* x = OZ * (AD + BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_mp_addmod(words, buf, bc, c->p);
    maid_mp_mov(words, a->x, o->z);
    maid_mp_mulmod(words, a->x, buf, c->p);
    maid_mp_mulmod(words, a->x, buf, c->p);

    /* z = OX * (AD - BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_mp_submod(words, buf, bc, c->p);
    maid_mp_mov(words, a->z, o->x);
    maid_mp_mulmod(words, a->z, buf, c->p);
    maid_mp_mulmod(words, a->z, buf, c->p);

    MAID_CLEAR_MP(ad)
    MAID_CLEAR_MP(bc)
    MAID_CLEAR_MP(buf)
}

static size_t
curve25519_size(void *ctx, size_t *key_s, size_t *point_s)
{
    struct curve25519 *c = ctx;
    size_t words = c->words;

    if (key_s)
        *key_s = 32;
    if (point_s)
        *point_s = 32;

    return words;
}

static bool
curve25519_keygen(void *ctx, u8 *data, maid_rng *g)
{
    (void)ctx;
    maid_rng_generate(g, data, 32);
    return true;
}

static bool
curve25519_scalar(void *ctx, const u8 *data, maid_mp_word *s)
{
    bool ret = true;

    struct curve25519 *c = ctx;

    u8 buffer[32] = {0};
    memcpy(buffer, data, 32);

    buffer[0]  &= 248;
    buffer[31] &= 63;
    buffer[31] |= 64;

    maid_mp_read(c->words, s, buffer, false);
    maid_mem_clear(buffer, sizeof(buffer));

    return ret;
}

static void
curve25519_debug(void *ctx, const char *name, const struct maid_ecc_point *a)
{
    struct curve25519 *c = ctx;
    fprintf(stderr, "%s (curve25519)\n", name);
    maid_mp_debug(c->words, "x", a->x);
    maid_mp_debug(c->words, "z", a->z);
}

const struct maid_ecc_def maid_curve25519 =
{
    .new    = curve25519_new,    .del    = curve25519_del,
    .alloc  = curve25519_alloc,  .free   = curve25519_free,
    .base   = curve25519_base,   .copy   = curve25519_copy,
    .encode = curve25519_encode, .decode = curve25519_decode,
    .cmp    = curve25519_cmp,    .dbl    = curve25519_dbl,
    .add2   = curve25519_add2,   .size   = curve25519_size,
    .keygen = curve25519_keygen, .scalar = curve25519_scalar,
    .debug  = curve25519_debug,
    .bits   = 256,
    .flags  = MAID_ECC_DIFF_ADD | MAID_ECC_NO_INF | MAID_ECC_LADDER_AD
};

/* Maid KEX definitions */

struct x25519
{
    size_t words;
    maid_ecc *c;
    maid_ecc_point *p;
    maid_mp_word *s;
};

extern void *
x25519_del(void *x25519)
{
    if (x25519)
    {
        struct x25519 *x = x25519;
        if (x->c)
            maid_ecc_free(x->c, x->p);
        maid_ecc_del(x->c);

        if (x->s)
            maid_mp_mov(x->words, x->s, NULL);
        free(x->s);
    }
    free(x25519);

    return NULL;
}

extern void *
x25519_new(void)
{
    struct x25519 *ret = calloc(1, sizeof(struct x25519));

    if (ret)
    {
        ret->words = maid_mp_words(256);
        ret->c = maid_ecc_new(maid_curve25519);
        ret->p = maid_ecc_alloc(ret->c);
        ret->s = calloc(ret->words, sizeof(maid_mp_word));
        if (!(ret->words && ret->c && ret->p && ret->s))
            ret = x25519_del(ret);
    }

    return ret;
}

extern bool
x25519_pubgen(void *x25519, const u8 *private, u8 *public)
{
    struct x25519 *x = x25519;
    return maid_ecc_pubgen(x->c, private, public);
}

extern bool
x25519_secgen(void *x25519, const u8 *private, const u8 *public, u8 *buffer)
{
    bool ret = false;

    struct x25519 *x = x25519;

    ret = maid_ecc_decode(x->c, public,  x->p) &&
          maid_ecc_scalar(x->c, private, x->s);
    if (ret)
    {
        maid_ecc_mul(x->c, x->p, x->s, true);
        ret = maid_ecc_encode(x->c, buffer, x->p);
    }

    return ret;
}

const struct maid_kex_def maid_x25519 =
{
    .new    = x25519_new,    .del    = x25519_del,
    .pubgen = x25519_pubgen, .secgen = x25519_secgen
};
