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

#include <maid/ecc.h>

struct maid_ecc
{
    struct maid_ecc_def def;
    void *context;

    size_t words;
    maid_ecc_point *r0, *r1, *r2;
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
                         && (ret->r2 = def.alloc(ret->context)))
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
    if (c && p && q)
        c->def.add(c->context, p, q);
}

extern void
maid_ecc_mul(struct maid_ecc *c, struct maid_ecc_point *p,
             const maid_mp_word *s, bool constant)
{
    if (c && p && s)
    {
        maid_ecc_copy(c, c->r0, NULL);
        maid_ecc_copy(c, c->r1, p);
        maid_ecc_copy(c, c->r2, NULL);

        size_t words = c->words;
        size_t maid_mp_bits = sizeof(maid_mp_word) * 8;

        volatile bool bit = false;
        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

            size_t e = ii / maid_mp_bits;
            u8     f = ii % maid_mp_bits;
            bit = ((s) ? s[e] : ((e == 0) ? 0x1 : 0x0)) & (1ULL << f);

            c->def.dbl(c->context, c->r0);
            if (bit)
                c->def.add(c->context, c->r0, c->r1);
            else if (constant)
                c->def.add(c->context, c->r2, c->r0);
        }
        bit = false;

        maid_ecc_copy(c, p, c->r0);
    }
}
