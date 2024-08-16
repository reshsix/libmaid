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
    void *ctx, *(*del)(void *);
    void (*encrypt)(void *, u8 *);
    void (*decrypt)(void *, u8 *);

    size_t state_s;
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
        bl->del(bl->ctx);

        if (bl->buffer)
            maid_mem_clear(bl->buffer, bl->state_s);
        free(bl->buffer);

        if (bl->iv)
            maid_mem_clear(bl->iv, bl->state_s);
        free(bl->iv);
    }
    free(bl);

    return NULL;
}

extern struct maid_block *
maid_block_new(void * (*new)(const u8, const u8 *),
               void * (*del)(void *),
               void (*encrypt)(void *, u8 *),
               void (*decrypt)(void *, u8 *),
               const size_t state_s,
               const u8 version, const u8 *restrict key,
               const u8 *restrict iv)
{
    struct maid_block *ret = calloc(1, sizeof(struct maid_block));

    if (ret)
    {
        ret->del = del;
        ret->encrypt = encrypt;
        ret->decrypt = decrypt;

        ret->ctx = new(version, key);
        ret->state_s = state_s;
        ret->iv  = calloc(1, state_s);

        ret->buffer = calloc(1, state_s);
        if (ret->ctx && ret->iv && ret->buffer)
            memcpy(ret->iv, iv, state_s);
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
            bl->encrypt(bl->ctx, buffer);
        else
            bl->decrypt(bl->ctx, buffer);
    }
}

extern void
maid_block_ctr(struct maid_block *bl, u8 *buffer, size_t size)
{
    if (bl && buffer && size)
    {
        while (size)
        {
            size_t aval = (bl->initialized) ? bl->state_s - bl->buffer_c: 0;

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

                memcpy(bl->buffer, bl->iv, bl->state_s);
                bl->encrypt(bl->ctx, bl->buffer);

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
