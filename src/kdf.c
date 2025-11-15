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

#include <maid/kdf.h>
#include <maid/mem.h>

#include <internal/types.h>

struct maid_kdf
{
    const struct maid_kdf_def *def;
    void *ctx;
};

extern struct maid_kdf *
maid_kdf_del(maid_kdf *k)
{
    if (k)
        k->def->del(k->ctx);
    free(k);

    return NULL;
}

extern struct maid_kdf *
maid_kdf_new(const struct maid_kdf_def *def,
             const void *params, size_t output_s)
{
    struct maid_kdf *ret = NULL;
    if (params)
        ret = calloc(1, sizeof(struct maid_kdf));

    if (ret)
    {
        ret->def = def;
        ret->ctx = def->new(def->version, params, output_s);
        if (!(ret->ctx))
            ret = maid_kdf_del(ret);
    }

    return ret;
}

extern void
maid_kdf_renew(struct maid_kdf *k, const void *params)
{
    if (k)
        k->def->renew(k->ctx, params);
}

extern void
maid_kdf_hash(struct maid_kdf *k, const u8 *data, size_t data_s,
              const u8 *salt, size_t salt_s, u8 *output)
{
    if (k)
        k->def->hash(k->ctx, data, data_s, salt, salt_s, output);
}
