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
    void *ctx, *(*del)(void *);
    void (*update)(void *, u8 *, size_t);
    void (*digest)(void *, u8 *);
    size_t state_s;

    u8 *buffer;
    size_t buffer_c;
    bool finished;
};

extern struct maid_mac *
maid_mac_del(maid_mac *m)
{
    if (m)
        m->del(m->ctx);
    free(m);

    return NULL;
}

extern struct maid_mac *
maid_mac_new(void * (*new)(const u8 *),
             void * (*del)(void *),
             void (*update)(void *, u8 *, size_t),
             void (*digest)(void *, u8 *),
             const size_t state_s, const u8 *key)
{
    struct maid_mac *ret = calloc(1, sizeof(struct maid_mac));

    if (ret)
    {
        ret->del = del;
        ret->update = update;
        ret->digest = digest;
        ret->state_s = state_s;

        ret->ctx = new(key);
        ret->buffer = calloc(1, state_s);
        if (!(ret->ctx && ret->buffer))
            ret = maid_mac_del(ret);
    }

    return ret;
}

extern void
maid_mac_update(struct maid_mac *m, u8 *buffer, size_t size)
{
    if (m && buffer && size && !(m->finished))
    {
        while (size)
        {
            u8 empty = m->state_s - m->buffer_c;
            u8 copy  = (size < empty) ? size : empty;

            memcpy(&(m->buffer[m->buffer_c]), buffer, copy);
            m->buffer_c += copy;
            if (m->buffer_c < m->state_s)
                break;

            m->update(m->ctx, m->buffer, m->state_s);
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
            m->update(m->ctx, m->buffer, m->buffer_c);

        m->digest(m->ctx, output);
        m->buffer_c = 0;

        m->finished = true;
    }
}
