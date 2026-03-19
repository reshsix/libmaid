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
#include <maid/hash.h>

#include <internal/hash.h>
#include <internal/types.h>

struct maid_hash
{
    const struct maid_hash_def *def;
    u8 state_s, digest_s;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
};

extern struct maid_hash *
maid_hash_init(void *buffer, size_t buffer_s,
               const struct maid_hash_def *def, u8 state_s, u8 digest_s)
{
    struct maid_hash *ret = buffer;

    if (ret)
    {
        maid_mem_clear(ret, buffer_s);

        ret->def    = def;
        ret->buffer = (void *)&(ret[1]);

        ret->ctx = &(ret->buffer[state_s]);
        if (def->init(ret->ctx, state_s, digest_s))
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
maid_hash_size(const struct maid_hash_def *def, u8 state_s, u8 digest_s)
{
    return sizeof(struct maid_hash) + def->size(state_s, digest_s) + state_s;
}

extern void
maid_hash_update(struct maid_hash *h, const u8 *buffer, size_t size)
{
    if (h && buffer && size)
    {
        while (size)
        {
            u8 empty = h->state_s - h->buffer_c;
            u8 copy  = (size < empty) ? size : empty;

            maid_mem_copy(&(h->buffer[h->buffer_c]), buffer, copy);
            h->buffer_c += copy;
            if (h->buffer_c < h->state_s)
                break;

            h->def->update(h->ctx, h->buffer, h->state_s);
            h->buffer_c = 0;
            maid_mem_clear(h->buffer, h->state_s);

            buffer = &(buffer[copy]);
            size -= copy;
        }
    }
}

extern size_t
maid_hash_digest(struct maid_hash *h, u8 *output)
{
    size_t ret = 0;

    if (h)
    {
        if (h->buffer_c)
            h->def->update(h->ctx, h->buffer, h->buffer_c);

        h->def->digest(h->ctx, output);
        h->buffer_c = 0;
        maid_mem_clear(h->buffer, h->state_s);

        ret = h->digest_s;
    }

    return ret;
}
