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

#include <string.h>

#include <maid/maid.h>

extern size_t
maid_block_ctr(void *ctx, u8 *buffer, size_t size)
{
    size_t ret = 0;

    if (ctx && buffer && size)
    {
        struct maid_block *b = ctx;

        ret = size;
        while (size)
        {
            size_t aval = (b->initialized) ? b->buffer_s - b->buffer_c: 0;

            if (aval >= size)
            {
                memcpy(buffer, b->buffer, size);
                b->buffer_c += size;
                size = 0;
            }
            else
            {
                /* Considering for AES (128 bit block) */
                u8 tmp[16] = {0};
                size_t bytes = b->read->f(b->read->ctx, tmp, b->buffer_s);

                if (bytes == 0)
                {
                    ret -= size;
                    break;
                }

                if (bytes < b->buffer_s && size > bytes)
                {
                    ret -= size - bytes;
                    size = bytes;
                }

                /* Big endian 32-bit counter, again AES specific */
                memcpy(b->buffer, b->nonce, b->buffer_s - 4);
                for (u8 i = 0; i < 4; i++)
                    b->buffer[b->buffer_s - 4 + i] =
                        (b->counter >> ((3 - i) * 8) & 0xFF);

                b->encrypt(b->context, b->buffer);
                for (size_t i = 0; i < b->buffer_s; i++)
                    b->buffer[i] ^= tmp[i];

                b->counter++;
                b->buffer_c = 0;
                b->initialized = true;

                maid_mem_clear(tmp, sizeof(tmp));
            }
        }
    }

    return ret;
}
