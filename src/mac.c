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

#include <maid/mac.h>
#include <maid/mem.h>

#include <internal/mac.h>
#include <internal/types.h>

struct maid_mac
{
    const struct maid_mac_def *def;
    u8 state_s, digest_s;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
};

extern struct maid_mac *
maid_mac_init(void *buffer, size_t buffer_s,
              const struct maid_mac_def *def,
              u8 key_s, u8 state_s, u8 digest_s)
{
    struct maid_mac *ret = buffer;
    maid_mem_clear(buffer, buffer_s);

    if (ret)
    {
        ret->def      = def;
        ret->buffer = (void *)&(ret[1]);

        ret->ctx = def->init(&(ret->buffer[state_s]),
                             key_s, state_s, digest_s);
        if (ret->ctx)
        {
            ret->state_s  = state_s;
            ret->digest_s = digest_s;
        }
        else
            ret = NULL;
    }

    return ret;
}

extern size_t
maid_mac_size(const struct maid_mac_def *def,
              u8 key_s, u8 state_s, u8 digest_s)
{
    return sizeof(struct maid_mac) + def->size(key_s, state_s, digest_s) +
           state_s;
}

extern void
maid_mac_config(struct maid_mac *m, const u8 *key)
{
    if (m && key)
        m->def->config(m->ctx, key);
}

extern void
maid_mac_update(struct maid_mac *m, const u8 *buffer, size_t size)
{
    if (m && buffer && size)
    {
        while (size)
        {
            u8 empty = m->state_s - m->buffer_c;
            u8 copy  = (size < empty) ? size : empty;

            maid_mem_copy(&(m->buffer[m->buffer_c]), buffer, copy);
            m->buffer_c += copy;
            if (m->buffer_c < m->state_s)
                break;

            m->def->update(m->ctx, m->buffer, m->state_s);
            m->buffer_c = 0;
            maid_mem_clear(m->buffer, m->state_s);

            buffer = &(buffer[copy]);
            size -= copy;
        }
    }
}

extern size_t
maid_mac_digest(struct maid_mac *m, u8 *output)
{
    size_t ret = 0;

    if (m && output)
    {
        if (m->buffer_c)
            m->def->update(m->ctx, m->buffer, m->buffer_c);

        m->def->digest(m->ctx, output);

        m->buffer_c = 0;
        maid_mem_clear(m->buffer, m->state_s);

        ret = m->digest_s;
    }

    return ret;
}
