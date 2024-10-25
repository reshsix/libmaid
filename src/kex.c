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

struct maid_kex
{
    struct maid_kex_def def;
    void *context;
};

extern struct maid_kex *
maid_kex_new(struct maid_kex_def def, const void *cfg, size_t bits)
{
    struct maid_kex *ret = NULL;
    if (cfg)
        ret = calloc(1, sizeof(struct maid_kex));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_kex_def));
        ret->context = def.new(cfg, bits);
        if (!(ret->context))
            ret = maid_kex_del(ret);
    }

    return ret;
}

extern void
maid_kex_renew(struct maid_kex *x, const void *cfg)
{
    if (x && cfg)
        x->def.renew(x->context, cfg);
}

extern struct maid_kex *
maid_kex_del(struct maid_kex *x)
{
    if (x)
        x->def.del(x->context);
    free(x);

    return NULL;
}

extern void
maid_kex_gpub(struct maid_kex *x, const void *private, void *public)
{
    if (x && private && public)
        x->def.gpub(x->context, private, public);
}

extern void
maid_kex_gsec(struct maid_kex *x, const void *private,
              const void *public, u8 *buffer)
{
    if (x && private && public && buffer)
        x->def.gsec(x->context, private, public, buffer);
}
