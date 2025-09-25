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

#include <maid/ecc.h>

struct maid_ecc
{
    struct maid_ecc_def def;
    void *context;

    size_t words;
    maid_ecc_point *r0, *r1, *r2, *r3;
};

extern struct maid_ecc *
maid_ecc_new(struct maid_ecc_def def)
{
    struct maid_ecc *ret = calloc(1, sizeof(struct maid_ecc));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_ecc_def));

        ret->context = def.new();
        if (ret->context && (ret->r0 = def.alloc(ret->context))
                         && (ret->r1 = def.alloc(ret->context))
                         && (ret->r2 = def.alloc(ret->context))
                         && (ret->r3 = def.alloc(ret->context)))
            ret->words = maid_mp_words(def.bits);
        else
            ret = maid_ecc_del(ret);
    }

    return ret;
}

extern struct maid_ecc *
maid_ecc_del(struct maid_ecc *c)
{
    if (c)
    {
        if (c->context)
        {
            c->def.free(c->context, c->r0);
            c->def.free(c->context, c->r1);
        }
        c->def.del(c->context);
    }
    free(c);

    return NULL;
}

extern struct maid_ecc_point *
maid_ecc_alloc(struct maid_ecc *c)
{
    maid_ecc_point *ret = NULL;

    if (c)
        ret = c->def.alloc(c->context);

    return ret;
}

extern struct maid_ecc_point *
maid_ecc_free(struct maid_ecc *c, struct maid_ecc_point *p)
{
    maid_ecc_point *ret = NULL;

    if (c)
        ret = c->def.free(c->context, p);

    return ret;
}

extern void
maid_ecc_base(struct maid_ecc *c, struct maid_ecc_point *p)
{
    if (c && p)
        c->def.base(c->context, p);
}

extern void
maid_ecc_copy(struct maid_ecc *c, struct maid_ecc_point *p,
              const struct maid_ecc_point *q)
{
    if (c && p)
        c->def.copy(c->context, p, q);
}

extern void
maid_ecc_swap(struct maid_ecc *c, struct maid_ecc_point *p,
              struct maid_ecc_point *q, bool swap)
{
    if (c && p && q)
        c->def.swap(c->context, p, q, swap);
}

extern bool
maid_ecc_encode(struct maid_ecc *c, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = false;

    if (c && buffer && p)
        ret = c->def.encode(c->context, buffer, p);

    return ret;
}

extern bool
maid_ecc_decode(struct maid_ecc *c, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = false;

    if (c && buffer && p)
        ret = c->def.decode(c->context, buffer, p);

    return ret;
}

extern bool
maid_ecc_cmp(struct maid_ecc *c, const struct maid_ecc_point *p,
                                 const struct maid_ecc_point *q)
{
    bool ret = false;

    if (c && p && q)
        ret = c->def.cmp(c->context, p, q);

    return ret;
}

extern void
maid_ecc_dbl(struct maid_ecc *c, struct maid_ecc_point *p)
{
    if (c && p)
        c->def.dbl(c->context, p);
}

extern void
maid_ecc_add(struct maid_ecc *c, struct maid_ecc_point *p,
             const struct maid_ecc_point *q)
{
    if (c && p && q && !(c->def.flags & MAID_ECC_DIFF_ADD))
        c->def.add(c->context, p, q);
}

static void
ladder_add(maid_ecc *c, struct maid_ecc_point *p,
           const struct maid_ecc_point *q,
           const struct maid_ecc_point *org)
{
    if (c->def.flags & MAID_ECC_DIFF_ADD)
        c->def.add2(c->context, p, q, org);
    else
        c->def.add(c->context, p, q);
}

extern void
maid_ecc_mul(struct maid_ecc *c, struct maid_ecc_point *p,
             const maid_mp_word *s)
{
    if (c && p && s)
    {
        maid_ecc_copy(c, c->r0, NULL);
        maid_ecc_copy(c, c->r1, p);
        maid_ecc_copy(c, c->r2, NULL);

        size_t words = c->words;
        size_t maid_mp_bits = sizeof(maid_mp_word) * 8;

        volatile bool bit = false, started = false;
        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

            size_t e = ii / maid_mp_bits;
            u8     f = ii % maid_mp_bits;
            bit = ((s) ? s[e] : ((e == 0) ? 0x1 : 0x0)) & (1ULL << f);
            started |= bit;

            if (c->def.flags & MAID_ECC_LADDER_AD)
            {
                if (c->def.flags & MAID_ECC_NO_CLAMP)
                    c->def.swap(c->context, c->r0, c->r2, !started);

                c->def.swap(c->context, c->r0, c->r1, !bit);

                ladder_add(c, c->r0, c->r1, p);
                c->def.dbl(c->context, c->r1);

                c->def.swap(c->context, c->r0, c->r1, !bit);

                if (c->def.flags & MAID_ECC_NO_CLAMP)
                    c->def.swap(c->context, c->r0, c->r2, !started);
            }
            else
            {
                if (c->def.flags & MAID_ECC_NO_CLAMP)
                    c->def.swap(c->context, c->r0, c->r3, !started);

                c->def.dbl(c->context, c->r0);
                c->def.swap(c->context, c->r0, c->r2, !bit);
                ladder_add(c, c->r0, c->r1, p);
                c->def.swap(c->context, c->r0, c->r2, !bit);

                if (c->def.flags & MAID_ECC_NO_CLAMP)
                    c->def.swap(c->context, c->r0, c->r3, !started);
            }
        }
        bit = false;

        maid_ecc_copy(c, p, c->r0);
    }
}

extern size_t
maid_ecc_size(struct maid_ecc *c, size_t *public_s, size_t *private_s)
{
    size_t ret = 0;

    if (c)
        ret = c->def.size(c->context, public_s, private_s);

    return ret;
}

extern u32
maid_ecc_flags(struct maid_ecc *c)
{
    u32 ret = 0;

    if (c)
        ret = c->def.flags;

    return ret;
}

extern bool
maid_ecc_keygen(struct maid_ecc *c, u8 *private, maid_rng *g)
{
    bool ret = false;

    if (c && private && g)
        ret = c->def.keygen(c->context, private, g);

    return ret;
}

extern bool
maid_ecc_pubgen(struct maid_ecc *c, const u8 *private, u8 *public)
{
    bool ret = false;

    if (c && private && public)
    {
        maid_ecc_point *p = maid_ecc_alloc(c);
        maid_mp_word s[c->words];
        if (c->def.scalar(c->context, private, s))
        {
            maid_ecc_base(c, p);
            maid_ecc_mul(c, p, s);
            ret = maid_ecc_encode(c, public, p);
        }
        maid_mp_mov(c->words, s, NULL);
        maid_ecc_free(c, p);
    }

    return ret;
}

extern bool
maid_ecc_scalar(struct maid_ecc *c, const u8 *private, maid_mp_word *s)
{
    bool ret = false;

    if (c && private && s)
        ret = c->def.scalar(c->context, private, s);

    return ret;
}

extern void
maid_ecc_debug(struct maid_ecc *c, const char *name,
               const struct maid_ecc_point *a)
{
    if (c)
        c->def.debug(c->context, name, a);
}
