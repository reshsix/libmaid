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

#include <maid/kex.h>

#include <internal/kex.h>
#include <internal/types.h>

struct maid_kex
{
    const struct maid_kex_def *def;
    void *context;
};

extern struct maid_kex *
maid_kex_new(const struct maid_kex_def *def)
{
    struct maid_kex *ret = calloc(1, sizeof(struct maid_kex));

    if (ret)
    {
        ret->def = def;
        ret->context = def->new();
        if (!(ret->context))
            ret = maid_kex_del(ret);
    }

    return ret;
}

extern struct maid_kex *
maid_kex_del(struct maid_kex *x)
{
    if (x)
        x->def->del(x->context);
    free(x);

    return NULL;
}

extern bool
maid_kex_pubgen(struct maid_kex *x, const u8 *prv, u8 *pub)
{
    bool ret = false;

    if (x && prv && pub)
        ret = x->def->pubgen(x->context, prv, pub);

    return ret;
}

extern bool
maid_kex_secgen(struct maid_kex *x, const u8 *prv,
                const u8 *pub, u8 *buffer)
{
    bool ret = false;

    if (x && prv && pub && buffer)
        ret = x->def->secgen(x->context, prv, pub, buffer);

    return ret;
}
