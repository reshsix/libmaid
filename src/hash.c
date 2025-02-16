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
#include <maid/hash.h>

struct maid_hash
{
    struct maid_hash_def def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool finished;
};

extern struct maid_hash *
maid_hash_del(maid_hash *m)
{
    if (m)
    {
        m->def.del(m->ctx);
        free(m->buffer);
    }
    free(m);

    return NULL;
}

extern struct maid_hash *
maid_hash_new(struct maid_hash_def def)
{
    struct maid_hash *ret = calloc(1, sizeof(struct maid_hash));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_hash_def));

        ret->ctx = def.new(def.version);
        ret->buffer = calloc(1, def.state_s);
        if (!(ret->ctx && ret->buffer))
            ret = maid_hash_del(ret);
    }

    return ret;
}

extern void
maid_hash_renew(struct maid_hash *m)
{
    if (m)
    {
        m->def.renew(m->ctx);

        m->buffer_c = 0;
        m->finished = false;
        maid_mem_clear(m->buffer, m->def.state_s);
    }
}

extern void
maid_hash_update(struct maid_hash *m, const u8 *buffer, size_t size)
{
    if (m && buffer && size && !(m->finished))
    {
        while (size)
        {
            u8 empty = m->def.state_s - m->buffer_c;
            u8 copy  = (size < empty) ? size : empty;

            memcpy(&(m->buffer[m->buffer_c]), buffer, copy);
            m->buffer_c += copy;
            if (m->buffer_c < m->def.state_s)
                break;

            m->def.update(m->ctx, m->buffer, m->def.state_s);
            m->buffer_c = 0;

            buffer = &(buffer[copy]);
            size -= copy;
        }
    }
}

extern size_t
maid_hash_digest(struct maid_hash *m, u8 *output)
{
    size_t ret = 0;

    if (m && output && !(m->finished))
    {
        if (m->buffer_c)
            m->def.update(m->ctx, m->buffer, m->buffer_c);

        m->def.digest(m->ctx, output);
        m->buffer_c = 0;

        m->finished = true;

        ret = m->def.digest_s;
    }

    return ret;
}
