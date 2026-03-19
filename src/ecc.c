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

#include <maid/mem.h>
#include <maid/ecc.h>

#include <internal/mp.h>
#include <internal/ecc.h>
#include <internal/types.h>

struct maid_ecc
{
    const struct maid_ecc_def *def;
    void *ctx;
    maid_ecc_point *r0, *r1, *r2, *r3;
};

extern struct maid_ecc *
maid_ecc_init(void *buffer, size_t buffer_s, const struct maid_ecc_def *def)
{
    struct maid_ecc *ret = buffer;

    if (ret)
    {
        maid_mem_clear(ret, buffer_s);

        ret->def = def;
        ret->ctx = def->init(&(ret[1]));

        size_t point_s = 0;
        size_t ctx_s   = def->size(&point_s);
        if (ret->ctx)
        {
            u8 *base = &(((u8*)ret->ctx)[ctx_s + 100]);
            ret->r0 = (void *)&(base[point_s * 0]);
            ret->r1 = (void *)&(base[point_s * 1]);
            ret->r2 = (void *)&(base[point_s * 2]);
            ret->r3 = (void *)&(base[point_s * 3]);
        }
        else
            ret = NULL;
    }

    return ret;
}

extern size_t
maid_ecc_size(const struct maid_ecc_def *def, size_t *point_s)
{
    size_t ret = 0;

    if (def)
    {
        size_t point_s2 = 0;
        size_t ctx_s    = def->size(&point_s2);
        if (point_s)
            *point_s = point_s2;

        ret = sizeof(struct maid_ecc) + ctx_s + (point_s2 * 4) + 100;
    }

    return ret;
}

extern void
maid_ecc_base(struct maid_ecc *c, struct maid_ecc_point *p)
{
    if (c && p)
        c->def->base(c->ctx, p);
}

extern void
maid_ecc_copy(struct maid_ecc *c, struct maid_ecc_point *p,
              const struct maid_ecc_point *q)
{
    if (c && p)
        c->def->copy(c->ctx, p, q);
}

extern void
maid_ecc_swap(struct maid_ecc *c, struct maid_ecc_point *p,
              struct maid_ecc_point *q, bool swap)
{
    if (c && p && q)
        c->def->swap(c->ctx, p, q, swap);
}

extern bool
maid_ecc_encode(struct maid_ecc *c, u8 *buffer, const struct maid_ecc_point *p)
{
    bool ret = false;

    if (c && buffer && p)
        ret = c->def->encode(c->ctx, buffer, p);

    return ret;
}

extern bool
maid_ecc_decode(struct maid_ecc *c, const u8 *buffer, struct maid_ecc_point *p)
{
    bool ret = false;

    if (c && buffer && p)
        ret = c->def->decode(c->ctx, buffer, p);

    return ret;
}

extern bool
maid_ecc_cmp(struct maid_ecc *c, const struct maid_ecc_point *p,
                                 const struct maid_ecc_point *q)
{
    bool ret = false;

    if (c && p && q)
        ret = c->def->cmp(c->ctx, p, q);

    return ret;
}

extern void
maid_ecc_dbl(struct maid_ecc *c, struct maid_ecc_point *p)
{
    if (c && p)
        c->def->dbl(c->ctx, p);
}

extern void
maid_ecc_add(struct maid_ecc *c, struct maid_ecc_point *p,
             const struct maid_ecc_point *q)
{
    if (c && p && q && !(c->def->flags & MAID_ECC_DIFF_ADD))
        c->def->add(c->ctx, p, q);
}

static void
ladder_add(maid_ecc *c, struct maid_ecc_point *p,
           const struct maid_ecc_point *q,
           const struct maid_ecc_point *org)
{
    if (c->def->flags & MAID_ECC_DIFF_ADD)
        c->def->add2(c->ctx, p, q, org);
    else
        c->def->add(c->ctx, p, q);
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

        size_t words = MAID_MP_WORDS(c->def->bits);
        size_t maid_mp_bits = sizeof(maid_mp_word) * 8;

        volatile bool bit = false, started = false;
        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

            size_t e = ii / maid_mp_bits;
            u8     f = ii % maid_mp_bits;
            bit = ((s) ? s[e] : ((e == 0) ? 0x1 : 0x0)) & (1ULL << f);
            started |= bit;

            if (c->def->flags & MAID_ECC_LADDER_AD)
            {
                if (c->def->flags & MAID_ECC_NO_CLAMP)
                    c->def->swap(c->ctx, c->r0, c->r2, !started);

                c->def->swap(c->ctx, c->r0, c->r1, !bit);

                ladder_add(c, c->r0, c->r1, p);
                c->def->dbl(c->ctx, c->r1);

                c->def->swap(c->ctx, c->r0, c->r1, !bit);

                if (c->def->flags & MAID_ECC_NO_CLAMP)
                    c->def->swap(c->ctx, c->r0, c->r2, !started);
            }
            else
            {
                if (c->def->flags & MAID_ECC_NO_CLAMP)
                    c->def->swap(c->ctx, c->r0, c->r3, !started);

                c->def->dbl(c->ctx, c->r0);
                c->def->swap(c->ctx, c->r0, c->r2, !bit);
                ladder_add(c, c->r0, c->r1, p);
                c->def->swap(c->ctx, c->r0, c->r2, !bit);

                if (c->def->flags & MAID_ECC_NO_CLAMP)
                    c->def->swap(c->ctx, c->r0, c->r3, !started);
            }
        }
        bit = false;

        maid_ecc_copy(c, p, c->r0);
    }
}

extern u8
maid_ecc_flags(struct maid_ecc *c)
{
    u32 ret = 0;

    if (c)
        ret = c->def->flags;

    return ret;
}

extern bool
maid_ecc_keygen(struct maid_ecc *c, u8 *private, maid_rng *g)
{
    bool ret = false;

    if (c && private && g)
        ret = c->def->keygen(c->ctx, private, g);

    return ret;
}

extern bool
maid_ecc_pubgen(struct maid_ecc *c, const u8 *private, u8 *public)
{
    bool ret = false;

    if (c && private && public)
    {
        size_t words   = MAID_MP_WORDS(c->def->bits);
        size_t point_s = 0;
        c->def->size(&point_s);
        u8 buffer[point_s];

        maid_ecc_point *p = (void *)buffer;
        maid_mp_word s[words];
        if (c->def->scalar(c->ctx, private, s))
        {
            maid_ecc_base(c, p);
            maid_ecc_mul(c, p, s);
            ret = maid_ecc_encode(c, public, p);
        }
        maid_mp_mov(words, s, NULL);
        maid_mem_clear(buffer, sizeof(buffer));
    }

    return ret;
}

extern bool
maid_ecc_scalar(struct maid_ecc *c, const u8 *private, maid_mp_word *s)
{
    bool ret = false;

    if (c && private && s)
        ret = c->def->scalar(c->ctx, private, s);

    return ret;
}
