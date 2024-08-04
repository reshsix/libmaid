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

#include <maid/maid.h>

extern size_t
maid_stream_xor(void *ctx, u8 *buffer, size_t size)
{
    size_t ret = 0;

    if (ctx && buffer && size)
    {
        struct maid_stream *s = ctx;
        size = s->read->f(s->read->ctx, buffer, size);

        ret = size;
        while (size)
        {
            size_t aval = (s->initialized) ? s->buffer_s - s->buffer_c: 0;

            if (aval >= size)
            {
                for (u8 i = 0; i < size; i++)
                    buffer[i] ^= s->buffer[s->buffer_c++];
                size = 0;
            }
            else
            {
                for (u8 i = 0; i < aval; i++)
                    buffer[i] ^= s->buffer[s->buffer_c++];
                buffer = &(buffer[aval]);
                size -= aval;

                s->keystream(s->context, s->nonce, s->counter++, s->buffer);
                s->buffer_c = 0;
                s->initialized = true;
            }
        }
    }

    return ret;
}
