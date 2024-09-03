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

#include <maid/utils.h>

#include <maid/mac.h>

struct maid_mac
{
    struct maid_mac_def def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool finished;
};

extern struct maid_mac *
maid_mac_del(maid_mac *m)
{
    if (m)
    {
        m->def.del(m->ctx);
        free(m->buffer);
    }
    free(m);

    return NULL;
}

extern struct maid_mac *
maid_mac_new(struct maid_mac_def def, const u8 *key)
{
    struct maid_mac *ret = calloc(1, sizeof(struct maid_mac));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_mac_def));

        ret->ctx = def.new(key);
        ret->buffer = calloc(1, def.state_s);
        if (!(ret->ctx && ret->buffer))
            ret = maid_mac_del(ret);
    }

    return ret;
}

extern void
maid_mac_renew(struct maid_mac *m, const u8 *key)
{
    if (m)
    {
        if (key)
            m->def.renew(m->ctx, key);

        m->buffer_c = 0;
        m->finished = false;
        maid_mem_clear(m->buffer, m->def.state_s);
    }
}

extern void
maid_mac_update(struct maid_mac *m, const u8 *buffer, size_t size)
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

extern void
maid_mac_digest(struct maid_mac *m, u8 *output)
{
    if (m && output && !(m->finished))
    {
        if (m->buffer_c)
            m->def.update(m->ctx, m->buffer, m->buffer_c);

        m->def.digest(m->ctx, output);
        m->buffer_c = 0;

        m->finished = true;
    }
}
