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

#include <maid/sign.h>

#include <internal/sign.h>
#include <internal/types.h>

struct maid_sign
{
    const struct maid_sign_def *def;
    void *context;
};

extern struct maid_sign *
maid_sign_new(const struct maid_sign_def *def, u8 *pub, u8 *prv)
{
    struct maid_sign *ret = NULL;
    if (pub || prv)
        ret = calloc(1, sizeof(struct maid_sign));

    if (ret)
    {
        ret->def = def;
        ret->context = def->new(def->version, pub, prv);
        if (!(ret->context))
            ret = maid_sign_del(ret);
    }

    return ret;
}

extern struct maid_sign *
maid_sign_del(struct maid_sign *s)
{
    if (s && s->context)
        s->def->del(s->context);
    free(s);

    return NULL;
}

extern size_t
maid_sign_size(struct maid_sign *s)
{
    size_t ret = 0;

    if (s)
        ret = s->def->size(s->context);

    return ret;
}

extern bool
maid_sign_generate(struct maid_sign *s, const u8 *data, size_t size, u8 *sign)
{
    bool ret = false;

    if (s && sign)
        ret = s->def->generate(s->context, data, size, sign);

    return ret;
}

extern bool
maid_sign_verify(struct maid_sign *s,
                 const u8 *data, size_t size, const u8 *sign)
{
    bool ret = false;

    if (s && sign)
        ret = s->def->verify(s->context, data, size, sign);

    return ret;
}
