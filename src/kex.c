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
#include <maid/kex.h>

#include <internal/kex.h>
#include <internal/types.h>

struct maid_kex
{
    const struct maid_kex_def *def;
    void *context;
};

extern struct maid_kex *
maid_kex_init(void *buffer, size_t buffer_s,
              const struct maid_kex_def *def)
{
    struct maid_kex *ret = buffer;

    if (ret)
    {
        maid_mem_clear(ret, buffer_s);

        ret->def = def;
        ret->context = (void *)&(ret[1]);
        if (!(def->init(ret->context)))
            ret = NULL;
    }

    return ret;
}

extern size_t
maid_kex_size(const struct maid_kex_def *def)
{
    return sizeof(struct maid_kex) + def->size();
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
