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

#include <maid/pub.h>

struct maid_pub
{
    struct maid_pub_def def;
    void *context;
};

extern struct maid_pub *
maid_pub_new(struct maid_pub_def def, const void *key, size_t bits)
{
    struct maid_pub *ret = NULL;
    if (key)
        ret = calloc(1, sizeof(struct maid_pub));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_pub_def));
        ret->context = def.new(def.version, key, bits);
    }

    return ret;
}

extern void
maid_pub_renew(struct maid_pub *p, const void *key)
{
    if (p && key)
        p->def.renew(p->context, key);
}

extern struct maid_pub *
maid_pub_del(struct maid_pub *p)
{
    if (p)
        p->def.del(p->context);
    free(p);

    return NULL;
}

extern void
maid_pub_apply(struct maid_pub *p, u8 *buffer)
{
    if (p && buffer)
        p->def.apply(p->context, buffer);
}
