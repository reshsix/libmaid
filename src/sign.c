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

#include <maid/sign.h>

struct maid_sign
{
    bool generate, verify;
    struct maid_sign_def def;
    void *context;
};

extern struct maid_sign *
maid_sign_new(struct maid_sign_def def, maid_pub *public,
              maid_pub *private, size_t bits)
{
    struct maid_sign *ret = NULL;
    if (public || private)
        ret = calloc(1, sizeof(struct maid_sign));

    if (ret)
    {
        ret->generate = (bool)private;
        ret->verify   = (bool)public;

        memcpy(&(ret->def), &def, sizeof(struct maid_sign_def));
        ret->context = def.new(def.version, public, private, bits);
        if (!(ret->context))
            ret = maid_sign_del(ret);
    }

    return ret;
}

extern void
maid_sign_renew(struct maid_sign *s, maid_pub *public, maid_pub *private)
{
    if (s && (public || private))
        s->def.renew(s->context, public, private);
}

extern struct maid_sign *
maid_sign_del(struct maid_sign *s)
{
    if (s)
        s->def.del(s->context);
    free(s);

    return NULL;
}

extern void
maid_sign_generate(struct maid_sign *s, u8 *buffer)
{
    if (s && buffer && s->generate)
        s->def.generate(s->context, buffer);
}

extern bool
maid_sign_verify(struct maid_sign *s, u8 *buffer)
{
    bool ret = false;

    if (s && buffer && s->verify)
        ret = s->def.verify(s->context, buffer);

    return ret;
}
