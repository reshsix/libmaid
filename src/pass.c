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

#include <maid/mem.h>
#include <maid/pass.h>

struct maid_pass
{
    struct maid_pass_def def;
    void *ctx;
};

extern struct maid_pass *
maid_pass_del(maid_pass *p)
{
    if (p)
        p->def.del(p->ctx);
    free(p);

    return NULL;
}

extern struct maid_pass *
maid_pass_new(struct maid_pass_def def, const void *params)
{
    struct maid_pass *ret = NULL;
    if (params)
        ret = calloc(1, sizeof(struct maid_pass));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_pass_def));

        ret->ctx = def.new(def.version, params);
        if (!(ret->ctx))
            ret = maid_pass_del(ret);
    }

    return ret;
}

extern void
maid_pass_renew(struct maid_pass *p, const void *params)
{
    if (p)
        p->def.renew(p->ctx, params);
}

extern void
maid_pass_hash(struct maid_pass *p, const char *pwd,
               const u8 *salt, size_t salt_s, u8 *output)
{
    if (p)
        p->def.hash(p->ctx, pwd, salt, salt_s, output);
}
