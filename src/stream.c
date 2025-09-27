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
#include <maid/stream.h>

struct maid_stream
{
    const struct maid_stream_def *def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool initialized;
};

extern struct maid_stream *
maid_stream_del(maid_stream *st)
{
    if (st)
    {
        st->def->del(st->ctx);

        if (st->buffer)
            maid_mem_clear(st->buffer, st->def->state_s);
        free(st->buffer);
    }
    free(st);

    return NULL;
}

extern struct maid_stream *
maid_stream_new(const struct maid_stream_def *def,
                const u8 *restrict key,
                const u8 *restrict nonce,
                u64 counter)
{
    struct maid_stream *ret = NULL;
    if (key && nonce)
        ret = calloc(1, sizeof(struct maid_stream));

    if (ret)
    {
        ret->def = def;
        ret->ctx = def->new(def->version, key, nonce, counter);
        ret->buffer = calloc(1, def->state_s);

        if (!(ret->ctx && ret->buffer))
            ret = maid_stream_del(ret);
    }

    return ret;
}

extern void
maid_stream_renew(struct maid_stream *st, const u8 *restrict key,
                  const u8 *restrict nonce, u64 counter)
{
    if (st)
    {
        st->def->renew(st->ctx, key, nonce, counter);
        st->buffer_c = 0;
        st->initialized = false;
        maid_mem_clear(st->buffer, st->def->state_s);
    }
}

extern void
maid_stream_xor(struct maid_stream *st, u8 *buffer, size_t size)
{
    if (st && buffer && size)
    {
        while (size)
        {
            size_t aval = (st->initialized) ? st->def->state_s -
                                              st->buffer_c: 0;
            if (aval >= size)
            {
                for (u8 i = 0; i < size; i++)
                    buffer[i] ^= st->buffer[st->buffer_c++];
                size = 0;
            }
            else
            {
                for (u8 i = 0; i < aval; i++)
                    buffer[i] ^= st->buffer[st->buffer_c++];
                buffer = &(buffer[aval]);
                size -= aval;

                st->def->generate(st->ctx, st->buffer);
                st->buffer_c = 0;
                st->initialized = true;
            }
        }
    }
}
