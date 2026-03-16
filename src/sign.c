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
#include <maid/sign.h>

#include <internal/sign.h>
#include <internal/types.h>

struct maid_sign
{
    const struct maid_sign_def *def;
    void *context;
};

extern struct maid_sign *
maid_sign_init(void *buffer, size_t buffer_s, const struct maid_sign_def *def)
{
    struct maid_sign *ret = buffer;
    maid_mem_clear(buffer, buffer_s);

    if (ret)
    {
        ret->def = def;
        ret->context = def->init(&(ret[1]));
        if (!(ret->context))
            ret = NULL;
    }

    return ret;
}

extern size_t
maid_sign_size(const struct maid_sign_def *def)
{
    return sizeof(struct maid_sign) + def->size();
}

extern bool
maid_sign_config(struct maid_sign *s, void *pub, void *prv)
{
    bool ret = false;

    if (s)
        ret = s->def->config(s->context, pub, prv);

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
