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

#include <internal/hash.h>
#include <internal/types.h>

struct maid_hash
{
    const struct maid_hash_def *def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool finished;
};

extern struct maid_hash *
maid_hash_del(maid_hash *h)
{
    if (h)
    {
        h->def->del(h->ctx);
        free(h->buffer);
    }
    free(h);

    return NULL;
}

extern struct maid_hash *
maid_hash_new(const struct maid_hash_def *def)
{
    struct maid_hash *ret = calloc(1, sizeof(struct maid_hash));

    if (ret)
    {
        ret->def = def;
        if (def->new)
        {
            ret->ctx = def->new(def->version);
            ret->buffer = calloc(1, def->state_s);
        }
        if (!(ret->ctx && ret->buffer))
            ret = maid_hash_del(ret);
    }

    return ret;
}

extern void
maid_hash_renew(struct maid_hash *h)
{
    if (h)
    {
        h->def->renew(h->ctx);

        h->buffer_c = 0;
        h->finished = false;
        maid_mem_clear(h->buffer, h->def->state_s);
    }
}

extern void
maid_hash_update(struct maid_hash *h, const u8 *buffer, size_t size)
{
    if (h && buffer && size && !(h->finished))
    {
        while (size)
        {
            u8 empty = h->def->state_s - h->buffer_c;
            u8 copy  = (size < empty) ? size : empty;

            memcpy(&(h->buffer[h->buffer_c]), buffer, copy);
            h->buffer_c += copy;
            if (h->buffer_c < h->def->state_s)
                break;

            h->def->update(h->ctx, h->buffer, h->def->state_s);
            h->buffer_c = 0;

            buffer = &(buffer[copy]);
            size -= copy;
        }
    }
}

extern size_t
maid_hash_digest(struct maid_hash *h, u8 *output)
{
    size_t ret = 0;

    if (h && output && !(h->finished))
    {
        if (h->buffer_c)
            h->def->update(h->ctx, h->buffer, h->buffer_c);

        h->def->digest(h->ctx, output);
        h->buffer_c = 0;

        h->finished = true;

        ret = h->def->digest_s;
    }

    return ret;
}
