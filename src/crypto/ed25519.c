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

/* Edwards25519 curve definition */

struct maid_ecc_point
{
    MAID_MP_SCALAR(x, 256);
    MAID_MP_SCALAR(y, 256);
    MAID_MP_SCALAR(z, 256);
    MAID_MP_SCALAR(t, 256);
};

struct edwards25519
{
    MAID_MP_SCALAR(d, 256);
    MAID_MP_SCALAR(x, 256);
    MAID_MP_SCALAR(y, 256);
    maid_hash *hash;

    maid_ff *ff;
    maid_mp_word *prime;
};

static void *
edwards25519_del(void *ctx)
{
    if (ctx)
    {
        struct edwards25519 *c = ctx;
        maid_hash_del(c->hash);
        maid_ff_del(c->ff);
        maid_mem_clear(ctx, sizeof(struct edwards25519));
    }
    free(ctx);

    return NULL;
}

static void *
edwards25519_new(void)
{
    struct edwards25519 *ret = calloc(1, sizeof(struct edwards25519));

    if (ret)
    {
        ret->hash = maid_hash_new(&maid_sha512);
        ret->ff   = maid_ff_new(MAID_FF_25519);
        if (ret->hash && ret->ff)
            ret->prime = maid_ff_prime(ret->ff);
        else
            ret = edwards25519_del(ret);
    }

    if (ret && !(import_mp(MAID_MP_WORDS(256), ret->d,
                       "52036cee2b6ffe738cc740797779e898"
                       "00700a4d4141d8ab75eb4dca135978a3") &&
                 import_mp(MAID_MP_WORDS(256), ret->x,
                       "216936d3cd6e53fec0a4e231fdd6dc5c"
                       "692cc7609525a7b2c9562d608f25d51a") &&
                 import_mp(MAID_MP_WORDS(256), ret->y,
                       "66666666666666666666666666666666"
                       "66666666666666666666666666666658")))
        ret = edwards25519_del(ret);

    return ret;
}

static void *
edwards25519_free(void *ctx, struct maid_ecc_point *p)
{
    (void)ctx;

    if (p)
        maid_mem_clear(p, sizeof(struct maid_ecc_point));

    free(p);
    return NULL;
}

static void *
edwards25519_alloc(void *ctx)
{
    return calloc(1, sizeof(struct maid_ecc_point));
}

static void
edwards25519_base(void *ctx, struct maid_ecc_point *p)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    maid_mp_mov(words, p->x, c->x);
    maid_mp_mov(words, p->y, c->y);

    maid_mp_mov(words, p->z, NULL);
    p->z[0] = 1;

    maid_mp_mov(words, p->t, c->x);
    maid_ff_mul(words, p->t, c->y, c->ff);
}

static void
edwards25519_copy(void *ctx, struct maid_ecc_point *p,
                  const struct maid_ecc_point *q)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    if (q)
    {
        maid_mp_mov(words, p->x, q->x);
        maid_mp_mov(words, p->y, q->y);
        maid_mp_mov(words, p->z, q->z);
        maid_mp_mov(words, p->t, q->t);
    }
    else
    {
        maid_mp_mov(words, p->x, NULL);
        maid_mp_mov(words, p->y, NULL);
        p->y[0] = 1;
        maid_mp_mov(words, p->z, NULL);
        p->z[0] = 1;
        maid_mp_mov(words, p->t, NULL);
    }
}

static void
edwards25519_swap(void *ctx, struct maid_ecc_point *p,
                  struct maid_ecc_point *q, bool swap)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    maid_mp_swap(words, p->x, q->x, swap);
    maid_mp_swap(words, p->y, q->y, swap);
    maid_mp_swap(words, p->z, q->z, swap);
    maid_mp_swap(words, p->t, q->t, swap);
}

static bool
edwards25519_encode(void *ctx, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = true;

    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);
    MAID_ALLOC_MP(buf, 1)

    /* buf = Z^-1 */
    maid_mp_mov(words, buf, p->z);
    ret = maid_ff_inv(words, buf, c->ff);
    if (ret)
    {
        MAID_ALLOC_MP(x, 1)
        MAID_ALLOC_MP(y, 1)

        /* x = X * Z^-1 mod p */
        maid_mp_mov(words, x, p->x);
        maid_ff_mul(words, x, buf, c->ff);
        /* y = Y * Z^-1 mod p */
        maid_mp_mov(words, y, p->y);
        maid_ff_mul(words, y, buf, c->ff);
        /* buffer = ((x & 1) << 255) | y */
        maid_mp_write(words, y, buffer, false);
        buffer[31] |= (x[0] & 1) << 7;

        MAID_CLEAR_MP(x)
        MAID_CLEAR_MP(y)
    }

    MAID_CLEAR_MP(buf)

    return ret;
}

static bool
edwards25519_decode(void *ctx, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = true;

    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);
    MAID_ALLOC_MP(y, 1)

    size_t xi = words - 1;
    size_t xj = (1ULL << ((sizeof(maid_mp_word) * 8) - 1));

    /* Read y (<p) and x-parity value */
    maid_mp_read(words, y, buffer, false);
    volatile bool xp = y[xi] & xj;
    y[xi] &= ~xj;
    ret = (maid_mp_cmp(words, y, c->prime) > 0);

    if (ret)
    {
        MAID_ALLOC_MP(u, 1)
        MAID_ALLOC_MP(v, 1)
        MAID_ALLOC_MP(x, 1)
        MAID_ALLOC_MP(buf, 1)

        buf[0] = 1;
        /* u = y^2 - 1 */
        maid_mp_mov(words, u, y);
        maid_ff_mul(words, u, y, c->ff);
        maid_ff_sub(words, u, buf, c->ff);
        /* v = dy^2 + 1 */
        maid_mp_mov(words, v, c->d);
        maid_ff_mul(words, v, y, c->ff);
        maid_ff_mul(words, v, y, c->ff);
        maid_ff_add(words, v, buf, c->ff);

        /* x = u/v ^ (p + 3)/8 */
        maid_mp_mov(words, x, v);
        ret = maid_ff_inv(words, x, c->ff);
        if (ret)
        {
            /* x = u/v */
            maid_ff_mul(words, x, u, c->ff);

            /* buf = (p + 3) / 8 */
            maid_mp_mov(words, buf, NULL);
            buf[0] = 3;
            maid_mp_add(words, buf, c->prime);
            maid_mp_shr(words, buf, 3);

            /* x = x^buf */
            maid_ff_exp(words, x, buf, c->ff);

            /* buf = vx^2 */
            maid_mp_mov(words, buf, x);
            maid_ff_mul(words, buf, x, c->ff);
            maid_ff_mul(words, buf, v, c->ff);

            /* If x is not a square root */
            if (maid_mp_cmp(words, buf, u) != 0)
            {
                /* v = -u */
                maid_mp_mov(words, v, NULL);
                maid_ff_sub(words, v, u, c->ff);

                /* xI might be */
                if (maid_mp_cmp(words, buf, v) == 0)
                {
                    MAID_ALLOC_MP(I, 1)

                    /* I = 2 ^ ((p - 1)/4) */
                    I[0] = 1;
                    maid_mp_mov(words, buf, c->prime);
                    maid_mp_sub(words, buf, I);
                    maid_mp_shr(words, buf, 2);
                    I[0] = 2;
                    maid_ff_exp(words, I, buf, c->ff);

                    /* x *= I */
                    maid_ff_mul(words, x, I, c->ff);

                    MAID_CLEAR_MP(I)
                }
                else
                    ret = false;
            }
        }

        if (ret)
        {
            /* x parity check */
            maid_mp_mov(words, buf, NULL);
            if ((((bool)(x[0] & 1)) != xp))
            {
                if (maid_mp_cmp(words, buf, x) != 0)
                {
                    maid_mp_mov(words, buf, x);
                    maid_mp_mov(words, x, c->prime);
                    maid_mp_sub(words, x, buf);
                }
                else
                    ret = false;
            }
        }

        /* X = x, Y = y, Z = 1, T = xy */
        if (ret)
        {
            maid_mp_mov(words, p->x, x);
            maid_mp_mov(words, p->y, y);
            maid_mp_mov(words, p->z, NULL);
            p->z[0] = 1;
            maid_mp_mov(words, p->t, x);
            maid_ff_mul(words, p->t, y, c->ff);
        }

        MAID_CLEAR_MP(u)
        MAID_CLEAR_MP(v)
        MAID_CLEAR_MP(x)
        MAID_CLEAR_MP(buf)
    }

    xp = false;
    MAID_CLEAR_MP(y)

    return ret;
}

static bool
edwards25519_cmp(void *ctx, const struct maid_ecc_point *a,
                            const struct maid_ecc_point *b)
{
    volatile bool ret = true;

    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    MAID_ALLOC_MP(buf, 1)
    MAID_ALLOC_MP(buf2, 1)
    MAID_ALLOC_MP(zi, 1)
    MAID_ALLOC_MP(zi2, 1)

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

    /* Y comparison */
    maid_mp_mov(words, buf,  a->y);
    maid_mp_mov(words, buf2, b->y);
    maid_ff_mul(words, buf,  zi,  c->ff);
    maid_ff_mul(words, buf2, zi2, c->ff);
    ret &= (maid_mp_cmp(words, buf, buf2) == 0);

    MAID_CLEAR_MP(buf)
    MAID_CLEAR_MP(buf2)
    MAID_CLEAR_MP(zi)
    MAID_CLEAR_MP(zi2)

    return ret;
}

static void
edwards25519_dbl(void *ctx, struct maid_ecc_point *a)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    /* Dbl-2008-hwcd, as recommended by RFC8032 */

    MAID_ALLOC_MP(ta, 1)
    MAID_ALLOC_MP(tb, 1)
    MAID_ALLOC_MP(tc, 1)
    MAID_ALLOC_MP(te, 1)
    MAID_ALLOC_MP(tf, 1)
    MAID_ALLOC_MP(tg, 1)
    MAID_ALLOC_MP(th, 1)
    MAID_ALLOC_MP(buf,  1)
    MAID_ALLOC_MP(buf2, 1)

    /* A = X1^2 */
    maid_mp_mov(words, ta, a->x);
    maid_ff_mul(words, ta, a->x, c->ff);
    /* B = Y1^2 */
    maid_mp_mov(words, tb, a->y);
    maid_ff_mul(words, tb, a->y, c->ff);
    /* C *= 2 * Z1^2 */
    maid_mp_mov(words, buf, a->z);
    maid_ff_mul(words, buf, a->z, c->ff);
    maid_ff_add(words, tc, buf, c->ff);
    maid_ff_add(words, tc, buf, c->ff);
    /* H = A + B */
    maid_mp_mov(words, th, ta);
    maid_ff_add(words, th, tb, c->ff);
    /* E = H - (X1 + Y1)^2 */
    maid_mp_mov(words, buf, a->x);
    maid_ff_add(words, buf, a->y, c->ff);
    maid_mp_mov(words, buf2, buf);
    maid_ff_mul(words, buf, buf2, c->ff);
    maid_mp_mov(words, te, th);
    maid_ff_sub(words, te, buf, c->ff);
    /* G = A - B */
    maid_mp_mov(words, tg, ta);
    maid_ff_sub(words, tg, tb, c->ff);
    /* F = C + G */
    maid_mp_mov(words, tf, tc);
    maid_ff_add(words, tf, tg, c->ff);
    /* X3 = E * F */
    maid_mp_mov(words, a->x, te);
    maid_ff_mul(words, a->x, tf, c->ff);
    /* Y3 = G * H */
    maid_mp_mov(words, a->y, tg);
    maid_ff_mul(words, a->y, th, c->ff);
    /* T3 = E * H */
    maid_mp_mov(words, a->t, te);
    maid_ff_mul(words, a->t, th, c->ff);
    /* Z3 = F * G */
    maid_mp_mov(words, a->z, tf);
    maid_ff_mul(words, a->z, tg, c->ff);

    MAID_CLEAR_MP(ta)
    MAID_CLEAR_MP(tb)
    MAID_CLEAR_MP(tc)
    MAID_CLEAR_MP(te)
    MAID_CLEAR_MP(tf)
    MAID_CLEAR_MP(tg)
    MAID_CLEAR_MP(th)
    MAID_CLEAR_MP(buf)
    MAID_CLEAR_MP(buf2)
}

static void
edwards25519_add(void *ctx, struct maid_ecc_point *a,
                 const struct maid_ecc_point *b)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    /* Add-2008-hwcd-3, as recommended by RFC8032 */

    MAID_ALLOC_MP(ta, 1)
    MAID_ALLOC_MP(tb, 1)
    MAID_ALLOC_MP(tc, 1)
    MAID_ALLOC_MP(td, 1)
    MAID_ALLOC_MP(te, 1)
    MAID_ALLOC_MP(tf, 1)
    MAID_ALLOC_MP(tg, 1)
    MAID_ALLOC_MP(th, 1)
    MAID_ALLOC_MP(buf, 1)

    /* A = (Y1 - X1) */
    maid_mp_mov(words, buf, a->y);
    maid_ff_sub(words, buf, a->x, c->ff);
    maid_mp_mov(words, ta, buf);
    /* A *= (Y2 - X2) */
    maid_mp_mov(words, buf, b->y);
    maid_ff_sub(words, buf, b->x, c->ff);
    maid_ff_mul(words, ta, buf, c->ff);
    /* B = (Y1 + X1) */
    maid_mp_mov(words, buf, a->y);
    maid_ff_add(words, buf, a->x, c->ff);
    maid_mp_mov(words, tb, buf);
    /* B *= (Y2 + X2) */
    maid_mp_mov(words, buf, b->y);
    maid_ff_add(words, buf, b->x, c->ff);
    maid_ff_mul(words, tb, buf, c->ff);
    /* C = T1 * 2 * d * T2 */
    maid_mp_mov(words, tc, a->t);
    maid_ff_add(words, tc, a->t, c->ff);
    maid_ff_mul(words, tc, c->d, c->ff);
    maid_ff_mul(words, tc, b->t, c->ff);
    /* D = Z1 * 2 * Z2 */
    maid_mp_mov(words, td, a->z);
    maid_ff_add(words, td, a->z, c->ff);
    maid_ff_mul(words, td, b->z, c->ff);
    /* E = B - A */
    maid_mp_mov(words, te, tb);
    maid_ff_sub(words, te, ta, c->ff);
    /* F = D - C */
    maid_mp_mov(words, tf, td);
    maid_ff_sub(words, tf, tc, c->ff);
    /* G = D + C */
    maid_mp_mov(words, tg, td);
    maid_ff_add(words, tg, tc, c->ff);
    /* H = B + A */
    maid_mp_mov(words, th, tb);
    maid_ff_add(words, th, ta, c->ff);
    /* X3 = E * F */
    maid_mp_mov(words, a->x, te);
    maid_ff_mul(words, a->x, tf, c->ff);
    /* Y3 = G * H */
    maid_mp_mov(words, a->y, tg);
    maid_ff_mul(words, a->y, th, c->ff);
    /* T3 = E * H */
    maid_mp_mov(words, a->t, te);
    maid_ff_mul(words, a->t, th, c->ff);
    /* Z3 = F * G */
    maid_mp_mov(words, a->z, tf);
    maid_ff_mul(words, a->z, tg, c->ff);

    MAID_CLEAR_MP(ta)
    MAID_CLEAR_MP(tb)
    MAID_CLEAR_MP(tc)
    MAID_CLEAR_MP(td)
    MAID_CLEAR_MP(te)
    MAID_CLEAR_MP(tf)
    MAID_CLEAR_MP(tg)
    MAID_CLEAR_MP(th)
    MAID_CLEAR_MP(buf)
}

static size_t
edwards25519_size(void *ctx, size_t *key_s, size_t *point_s)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    if (key_s)
        *key_s = 34;
    if (point_s)
        *point_s = 32;

    return words;
}

static bool
edwards25519_keygen(void *ctx, u8 *data, maid_rng *g)
{
    (void)ctx;
    maid_rng_generate(g, data, 32);
    return true;
}

static bool
edwards25519_scalar(void *ctx, const u8 *data, maid_mp_word *s)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    u8 buffer[64] = {0};
    maid_hash_update(c->hash, data, 32);
    maid_hash_digest(c->hash, buffer);
    maid_hash_renew(c->hash);

    buffer[0]  &= 248;
    buffer[31] &= 63;
    buffer[31] |= 64;

    maid_mp_read(words, s, buffer, false);
    maid_mem_clear(buffer, sizeof(buffer));

    return true;
}

static void
edwards25519_debug(void *ctx, const char *name, const struct maid_ecc_point *a)
{
    struct edwards25519 *c = ctx;
    size_t words = MAID_MP_WORDS(256);

    fprintf(stderr, "%s (edwards25519)\n", name);
    maid_mp_debug(words, "x", a->x);
    maid_mp_debug(words, "y", a->y);
    maid_mp_debug(words, "z", a->z);
    maid_mp_debug(words, "t", a->t);
}

const struct maid_ecc_def maid_edwards25519 =
{
    .new    = edwards25519_new,    .del    = edwards25519_del,
    .alloc  = edwards25519_alloc,  .free   = edwards25519_free,
    .base   = edwards25519_base,   .copy   = edwards25519_copy,
    .swap   = edwards25519_swap,
    .encode = edwards25519_encode, .decode = edwards25519_decode,
    .cmp    = edwards25519_cmp,    .dbl    = edwards25519_dbl,
    .add    = edwards25519_add,    .size   = edwards25519_size,
    .keygen = edwards25519_keygen, .scalar = edwards25519_scalar,
    .debug  = edwards25519_debug,
    .bits   = 256
};

/* Ed25519 signature definition */

struct ed25519
{
    bool sign, verify;

    /* Used in both */
    maid_ecc *ecc;
    maid_hash *hash;
    struct maid_ecc_point point;
    maid_ff *ff;
    maid_mp_word *prime;
    u8 pubenc[32];

    /* Used in generation */
    u8 prefix[32];
    MAID_MP_SCALAR(scalar, 512);

    /* Used in verification */
    struct maid_ecc_point public;
    struct maid_ecc_point point2;

    /* 512 bits to support SHA-512 hash */
};

static void *
ed25519_del(void *ed25519)
{
    struct ed25519 *ed = ed25519;

    maid_ecc_del(ed->ecc);
    maid_hash_del(ed->hash);
    maid_ff_del(ed->ff);
    maid_mem_clear(ed25519, sizeof(struct ed25519));

    free(ed25519);
    return NULL;
}

static void *
ed25519_new(u8 version, void *pub, void *prv)
{
    struct ed25519 *ret = calloc(1, sizeof(struct ed25519));

    (void)version;
    if (ret)
    {
        /* Allocation */
        ret->ecc  = maid_ecc_new(&maid_edwards25519);
        ret->hash = maid_hash_new(&maid_sha512);
        if (!(ret->ecc && ret->hash))
            ret = ed25519_del(ret);

        if (ret && prv)
            ret->sign   = true;
        if (ret && pub)
            ret->verify = true;

        /* Private key loading */
        if (ret && prv)
        {
            u8 *data = prv;

            u8 buffer[64] = {0};
            maid_hash_update(ret->hash, data, 32);
            maid_hash_digest(ret->hash, buffer);
            maid_hash_renew(ret->hash);

            buffer[0]  &= 248;
            buffer[31] &= 63;
            buffer[31] |= 64;

            maid_mp_read(MAID_MP_WORDS(256), ret->scalar, buffer, false);
            memcpy(ret->prefix, &(buffer[32]), 32);
            maid_mem_clear(buffer, sizeof(buffer));
        }

        /* Public key loading */
        if (ret)
        {
            if (pub)
            {
                memcpy(ret->pubenc, pub, 32);
                if (!maid_ecc_decode(ret->ecc, ret->pubenc, &(ret->public)))
                    ret = ed25519_del(ret);
            }
            else
            {
                /* Pubenc is needed even for signing */
                maid_ecc_base(ret->ecc, &(ret->point));
                maid_ecc_mul(ret->ecc, &(ret->point), ret->scalar);
                if (!maid_ecc_encode(ret->ecc, ret->pubenc, &(ret->point)))
                    ret = ed25519_del(ret);
            }
        }

        /* Copy curve order (modulo) */
        if (ret)
        {
            ret->ff = maid_ff_new(MAID_FF_ORDER25519);
            if (ret->ff)
                ret->prime = maid_ff_prime(ret->ff);
            else
                ret = ed25519_del(ret);
        }
    }

    return ret;
}

static size_t
ed25519_size(void *ed)
{
    (void)ed;
    return 64;
}

static bool
ed25519_generate(void *ed25519, const u8 *data, size_t size, u8 *sign)
{
    bool ret = true;

    struct ed25519 *ed = ed25519;
    size_t words = MAID_MP_WORDS(256);

    if (ed->sign)
    {
        u8 hash[64] = {0};
        /* r = SHA512(prefix data) % modulo */
        maid_mp_word r[words * 2];
        maid_hash_renew(ed->hash);
        maid_hash_update(ed->hash, ed->prefix, 32);
        maid_hash_update(ed->hash, data, size);
        maid_hash_digest(ed->hash, hash);
        maid_mp_read(words * 2, r, hash, false);
        maid_ff_mod(words * 2, r, ed->ff);

        /* First part of the signature (R = rB) */
        maid_ecc_base(ed->ecc, &(ed->point));
        maid_ecc_mul(ed->ecc, &(ed->point), r);
        maid_ecc_encode(ed->ecc, sign, &(ed->point));

        /* k = SHA512(R public data) % modulo */
        maid_mp_word k[words * 2];
        maid_hash_renew(ed->hash);
        maid_hash_update(ed->hash, sign, 32);
        maid_hash_update(ed->hash, ed->pubenc, 32);
        maid_hash_update(ed->hash, data, size);
        maid_hash_digest(ed->hash, hash);
        maid_mp_read(words * 2, k, hash, false);
        maid_ff_mod(words * 2, k, ed->ff);

        /* Second part of the signature (s = (r + ka) % modulo) */
        maid_ff_mul(words, k, ed->scalar, ed->ff);
        maid_ff_add(words, k, r, ed->ff);
        maid_mp_write(words, k, &(sign[32]), false);

        /* Cleaning up */
        maid_mem_clear(hash, sizeof(hash));
        maid_mp_mov(words * 2, r, NULL);
        maid_mp_mov(words * 2, k, NULL);
    }
    else
        ret = false;

    return ret;
}

static bool
ed25519_verify(void *ed25519, const u8 *data, size_t size, const u8 *sign)
{
    bool ret = true;

    struct ed25519 *ed = ed25519;
    size_t words = MAID_MP_WORDS(256);

    if (ed->verify)
    {
        /* R decoding */
        ret &= maid_ecc_decode(ed->ecc, sign, &(ed->point));

        /* s decoding */
        maid_mp_word s[words];
        maid_mp_read(words, s, &(sign[32]), false);
        ret &= (maid_mp_cmp(words, s, ed->prime) > 0);

        maid_mp_word k[words * 2];
        /* k = SHA512(R public data) % modulo */
        u8 hash[64] = {0};
        maid_hash_renew(ed->hash);
        maid_hash_update(ed->hash, sign, 32);
        maid_hash_update(ed->hash, ed->pubenc, 32);
        maid_hash_update(ed->hash, data, size);
        maid_hash_digest(ed->hash, hash);
        maid_mp_read(words * 2, k, hash, false);
        maid_ff_mod(words * 2, k, ed->ff);

        /* point2 = R + kP */
        maid_ecc_copy(ed->ecc, &(ed->point2), &(ed->public));
        maid_ecc_mul(ed->ecc, &(ed->point2), k);
        maid_ecc_add(ed->ecc, &(ed->point2), &(ed->point));

        /* point = sB */
        maid_ecc_base(ed->ecc, &(ed->point));
        maid_ecc_mul(ed->ecc, &(ed->point), s);

        /* sB ?= R + kP */
        ret &= maid_ecc_cmp(ed->ecc, &(ed->point), &(ed->point2));
        maid_mem_clear(hash, sizeof(hash));

        maid_mp_mov(words, s, NULL);
        maid_mp_mov(words, k, NULL);
    }
    else
        ret = false;

    return ret;
}

const struct maid_sign_def maid_ed25519 =
{
    .new      = ed25519_new,
    .del      = ed25519_del,
    .size     = ed25519_size,
    .generate = ed25519_generate,
    .verify   = ed25519_verify,
    .version  = 0
};
