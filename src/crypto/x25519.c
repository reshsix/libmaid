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

#include <maid/ff.h>
#include <maid/mp.h>
#include <maid/ecc.h>
#include <maid/kex.h>
#include <maid/mem.h>
#include <maid/hash.h>
#include <maid/sign.h>

#include <internal/mp.h>
#include <internal/ecc.h>
#include <internal/kex.h>
#include <internal/types.h>

/* Curve25519 curve definition */

struct maid_ecc_point
{
    MAID_MP_SCALAR(x, 256);
    MAID_MP_SCALAR(z, 256);
};

struct curve25519
{
    maid_ff *ff;
    maid_mp_word *prime;
};

static void *
curve25519_del(void *ctx)
{
    if (ctx)
    {
        struct curve25519 *c = ctx;
        maid_ff_del(c->ff);
        maid_mem_clear(ctx, sizeof(struct curve25519));
    }
    free(ctx);
    return NULL;
}

static void *
curve25519_new(void)
{
    struct curve25519 *ret = calloc(1, sizeof(struct curve25519));

    if (ret)
    {
        ret->ff = maid_ff_new(MAID_FF_25519);
        if (ret->ff)
            ret->prime = maid_ff_prime(ret->ff);
        else
            ret = curve25519_del(ret);
    }

    return ret;
}

static void *
curve25519_free(void *ctx, struct maid_ecc_point *p)
{
    (void)ctx;

    if (p)
        maid_mem_clear(p, sizeof(struct maid_ecc_point));
    free(p);

    return NULL;
}

static void *
curve25519_alloc(void *ctx)
{
    (void)ctx;
    return calloc(1, sizeof(struct maid_ecc_point));
}

static void
curve25519_base(void *ctx, struct maid_ecc_point *p)
{
    (void)ctx;
    size_t words = MAID_MP_WORDS(256);

    maid_mp_mov(words, p->x, NULL);
    maid_mp_mov(words, p->z, NULL);
    p->x[0] = 9;
    p->z[0] = 1;
}

static void
curve25519_copy(void *ctx, struct maid_ecc_point *p,
                const struct maid_ecc_point *q)
{
    (void)ctx;
    size_t words = MAID_MP_WORDS(256);

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

static void
curve25519_swap(void *ctx, struct maid_ecc_point *p,
                struct maid_ecc_point *q, bool swap)
{
    (void)ctx;
    size_t words = MAID_MP_WORDS(256);

    maid_mp_swap(words, p->x, q->x, swap);
    maid_mp_swap(words, p->z, q->z, swap);
}

static bool
curve25519_encode(void *ctx, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);
    MAID_MP_ALLOC(buf, 1)

    maid_mp_mov(words, buf, p->z);
    ret = maid_ff_inv(words, buf, c->ff);
    if (ret)
    {
        maid_ff_mul(words, buf, p->x, c->ff);
        maid_mp_write(words, buf, buffer, false);
    }

    MAID_MP_CLEAR(buf)

    return ret;
}

static bool
curve25519_decode(void *ctx, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = true;

    struct curve25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);
    MAID_MP_ALLOC(buf, 1)

    maid_mp_read(words, buf, buffer, false);
    ret = (maid_mp_cmp(words, buf, c->prime) > 0);
    if (ret)
    {
        maid_mp_mov(words, p->x, buf);
        maid_mp_mov(words, p->z, NULL);
        p->z[0] = 1;
    }

    MAID_MP_CLEAR(buf)

    return ret;
}

static bool
curve25519_cmp(void *ctx, const struct maid_ecc_point *a,
                          const struct maid_ecc_point *b)
{
    volatile bool ret = true;

    struct curve25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    MAID_MP_ALLOC(buf, 1)
    MAID_MP_ALLOC(buf2, 1)
    MAID_MP_ALLOC(zi, 1)
    MAID_MP_ALLOC(zi2, 1)

    /* Inverse Z calculation */
    maid_mp_mov(words, zi,  a->z);
    maid_mp_mov(words, zi2, b->z);
    ret &= maid_ff_inv(words, zi,  c->ff);
    ret &= maid_ff_inv(words, zi2, c->ff);

    /* X comparison */
    maid_mp_mov(words, buf,  a->x);
    maid_mp_mov(words, buf2, b->x);
    maid_ff_mul(words, buf,  zi,  c->ff);
    maid_ff_mul(words, buf2, zi2, c->ff);
    ret &= (maid_mp_cmp(words, buf, buf2) == 0);

    MAID_MP_CLEAR(buf)
    MAID_MP_CLEAR(buf2)
    MAID_MP_CLEAR(zi)
    MAID_MP_CLEAR(zi2)

    return ret;
}

static void
curve25519_dbl(void *ctx, struct maid_ecc_point *a)
{
    struct curve25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    MAID_MP_ALLOC(aa,  1)
    MAID_MP_ALLOC(bb,  1)
    MAID_MP_ALLOC(cc,  1)
    MAID_MP_ALLOC(buf, 1)

    /* AA = (X + Z)^2 */
    maid_mp_mov(words, buf, a->x);
    maid_ff_add(words, buf, a->z, c->ff);
    maid_mp_mov(words, aa, buf);
    maid_ff_mul(words, aa, buf, c->ff);

    /* BB = (X - Z)^2 */
    maid_mp_mov(words, buf, a->x);
    maid_ff_sub(words, buf, a->z, c->ff);
    maid_mp_mov(words, bb, buf);
    maid_ff_mul(words, bb, buf, c->ff);

    /* CC = AA - BB */
    maid_mp_mov(words, cc, aa);
    maid_ff_sub(words, cc, bb, c->ff);

    /* x = AA * BB */
    maid_mp_mov(words, a->x, aa);
    maid_ff_mul(words, a->x, bb, c->ff);

    /* z = ((121666 * CC) + BB) * CC */
    maid_mp_mov(words, a->z, NULL);
    a->z[0] = 121666;
    maid_ff_mul(words, a->z, cc, c->ff);
    maid_ff_add(words, a->z, bb, c->ff);
    maid_ff_mul(words, a->z, cc, c->ff);

    MAID_MP_CLEAR(aa)
    MAID_MP_CLEAR(bb)
    MAID_MP_CLEAR(cc)
    MAID_MP_CLEAR(buf)
}

static void
curve25519_add2(void *ctx, struct maid_ecc_point *a,
                const struct maid_ecc_point *b,
                const struct maid_ecc_point *o)
{
    struct curve25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    /* Differential addition, only works with the ladder */
    MAID_MP_ALLOC(ad,  1)
    MAID_MP_ALLOC(bc,  1)
    MAID_MP_ALLOC(buf, 1)

    /* AD = (X1 + Z1) * (X2 - Z2) */
    maid_mp_mov(words, ad, a->x);
    maid_ff_add(words, ad, a->z, c->ff);
    maid_mp_mov(words, buf, b->x);
    maid_ff_sub(words, buf, b->z, c->ff);
    maid_ff_mul(words, ad, buf, c->ff);

    /* BC = (X1 - Z1) * (X2 + Z2) */
    maid_mp_mov(words, bc, a->x);
    maid_ff_sub(words, bc, a->z, c->ff);
    maid_mp_mov(words, buf, b->x);
    maid_ff_add(words, buf, b->z, c->ff);
    maid_ff_mul(words, bc, buf, c->ff);

    /* x = OZ * (AD + BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_ff_add(words, buf, bc, c->ff);
    maid_mp_mov(words, a->x, o->z);
    maid_ff_mul(words, a->x, buf, c->ff);
    maid_ff_mul(words, a->x, buf, c->ff);

    /* z = OX * (AD - BC)^2 */
    maid_mp_mov(words, buf, ad);
    maid_ff_sub(words, buf, bc, c->ff);
    maid_mp_mov(words, a->z, o->x);
    maid_ff_mul(words, a->z, buf, c->ff);
    maid_ff_mul(words, a->z, buf, c->ff);

    MAID_MP_CLEAR(ad)
    MAID_MP_CLEAR(bc)
    MAID_MP_CLEAR(buf)
}

static size_t
curve25519_size(void *ctx, size_t *key_s, size_t *point_s)
{
    (void)ctx;

    if (key_s)
        *key_s = 32;
    if (point_s)
        *point_s = 32;

    return MAID_MP_WORDS(256);
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

    (void)ctx;
    size_t words = MAID_MP_WORDS(256);

    u8 buffer[32] = {0};
    memcpy(buffer, data, 32);

    buffer[0]  &= 248;
    buffer[31] &= 63;
    buffer[31] |= 64;

    maid_mp_read(words, s, buffer, false);
    maid_mem_clear(buffer, sizeof(buffer));

    return ret;
}

static void
curve25519_debug(void *ctx, const char *name, const struct maid_ecc_point *a)
{
    (void)ctx;
    size_t words = MAID_MP_WORDS(256);

    fprintf(stderr, "%s (curve25519)\n", name);
    maid_mp_debug(words, "x", a->x);
    maid_mp_debug(words, "z", a->z);
}

static const struct maid_ecc_def curve25519_def =
{
    .new    = curve25519_new,    .del    = curve25519_del,
    .alloc  = curve25519_alloc,  .free   = curve25519_free,
    .base   = curve25519_base,   .copy   = curve25519_copy,
    .swap   = curve25519_swap,
    .encode = curve25519_encode, .decode = curve25519_decode,
    .cmp    = curve25519_cmp,    .dbl    = curve25519_dbl,
    .add2   = curve25519_add2,   .size   = curve25519_size,
    .keygen = curve25519_keygen, .scalar = curve25519_scalar,
    .debug  = curve25519_debug,
    .bits   = 256,
    .flags  = MAID_ECC_DIFF_ADD | MAID_ECC_NO_INF | MAID_ECC_LADDER_AD
};

extern maid_ecc *
maid_curve25519(void)
{
    return maid_ecc_new(&curve25519_def);
}

/* Maid KEX definitions */

struct x25519
{
    maid_ecc *c;
    struct maid_ecc_point p;
    MAID_MP_SCALAR(s, 256);
};

static void *
x25519_del(void *x25519)
{
    if (x25519)
        maid_mem_clear(x25519, sizeof(struct x25519));
    free(x25519);

    return NULL;
}

static void *
x25519_new(void)
{
    return calloc(1, sizeof(struct x25519));
}

static bool
x25519_pubgen(void *x25519, const u8 *private, u8 *public)
{
    struct x25519 *x = x25519;
    return maid_ecc_pubgen(x->c, private, public);
}

static bool
x25519_secgen(void *x25519, const u8 *private, const u8 *public, u8 *buffer)
{
    bool ret = false;

    struct x25519 *x = x25519;

    ret = maid_ecc_decode(x->c, public,  &(x->p)) &&
          maid_ecc_scalar(x->c, private, x->s);
    if (ret)
    {
        maid_ecc_mul(x->c, &(x->p), x->s);
        ret = maid_ecc_encode(x->c, buffer, &(x->p));
    }

    return ret;
}

static const struct maid_kex_def x25519_def =
{
    .new    = x25519_new,    .del    = x25519_del,
    .pubgen = x25519_pubgen, .secgen = x25519_secgen
};

extern maid_kex *
maid_x25519(void)
{
    return maid_kex_new(&x25519_def);
}
