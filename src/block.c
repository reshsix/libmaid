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

#include <maid/block.h>

struct maid_block
{
    struct maid_block_def def;
    void *ctx;

    u8 *iv;

    /* For ctr mode */
    u8 *buffer;
    size_t buffer_c;
    bool initialized;
};

extern struct maid_block *
maid_block_del(maid_block *bl)
{
    if (bl)
    {
        bl->def.del(bl->ctx);

        if (bl->buffer)
            maid_mem_clear(bl->buffer, bl->def.state_s);
        free(bl->buffer);

        if (bl->iv)
            maid_mem_clear(bl->iv, bl->def.state_s);
        free(bl->iv);
    }
    free(bl);

    return NULL;
}

extern struct maid_block *
maid_block_new(struct maid_block_def def,
               const u8 *restrict key,
               const u8 *restrict iv)
{
    struct maid_block *ret = calloc(1, sizeof(struct maid_block));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_block_def));
        ret->ctx = def.new(def.version, key);
        ret->iv  = calloc(1, def.state_s);

        ret->buffer = calloc(1, def.state_s);
        if (ret->ctx && ret->iv && ret->buffer)
            memcpy(ret->iv, iv, def.state_s);
        else
            ret = maid_block_del(ret);
    }

    return ret;
}

extern void
maid_block_ecb(struct maid_block *bl, u8 *buffer, bool decrypt)
{
    if (bl && buffer)
    {
        if (!decrypt)
            bl->def.encrypt(bl->ctx, buffer);
        else
            bl->def.decrypt(bl->ctx, buffer);
    }
}

extern void
maid_block_ctr(struct maid_block *bl, u8 *buffer, size_t size)
{
    if (bl && buffer && size)
    {
        while (size)
        {
            size_t aval = (bl->initialized) ? bl->def.state_s -
                                              bl->buffer_c: 0;
            if (aval >= size)
            {
                for (u8 i = 0; i < size; i++)
                    buffer[i] ^= bl->buffer[bl->buffer_c++];
                size = 0;
            }
            else
            {
                for (u8 i = 0; i < aval; i++)
                    buffer[i] ^= bl->buffer[bl->buffer_c++];
                buffer = &(buffer[aval]);
                size -= aval;

                memcpy(bl->buffer, bl->iv, bl->def.state_s);
                bl->def.encrypt(bl->ctx, bl->buffer);

                /* Increases counter in big-endian way */
                volatile u8 carry = 1;
                for (u8 i = 15; i < 16; i--)
                {
                    volatile u16 sum = carry + bl->iv[i];

                    bl->iv[i] = sum & 0xFF;
                    carry = sum >> 8;

                    sum = 0;
                }
                carry = 0;

                bl->buffer_c = 0;
                bl->initialized = true;
            }
        }
    }
}
