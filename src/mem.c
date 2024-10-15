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

#include <maid/types.h>

extern u64
maid_mem_read(const void *addr, size_t index, size_t size, bool big)
{
    u64 ret = 0;

    if (addr && size <= sizeof(u64))
    {
        const u8 *src = addr;
        src = &(src[index * size]);

        if (!big)
        {
            for (u8 i = 0; i < size; i++)
                ret |= ((u64)src[i]) << (8 * i);
        }
        else
        {
            for (u8 i = 0; i < size; i++)
                ret |= ((u64)src[size - i - 1]) << (8 * i);
        }
    }

    return ret;
}

extern void
maid_mem_write(void *addr, size_t index, size_t size, bool big, u64 data)
{
    if (addr && size <= sizeof(u64))
    {
        u8 *src = addr;
        src = &(src[index * size]);

        if (!big)
        {
            for (u8 i = 0; i < size; i++)
                src[i] = (data >> (8 * i)) & 0xFF;
        }
        else
        {
            for (u8 i = 0; i < size; i++)
                src[size - i - 1] = (data >> (8 * i)) & 0xFF;
        }
    }
}

extern void
maid_mem_clear(void *addr, size_t length)
{
    if (addr)
    {
        volatile u8 *dest = addr;
        for (size_t i = 0; i < length; i++)
            dest[i] = 0x0;
    }
}

extern bool
maid_mem_cmp(void *addr, void *addr2, size_t length)
{
    volatile bool ret = true;

    if (addr && addr2)
    {
        volatile u8 *a = addr;
        volatile u8 *b = addr2;
        for (size_t i = 0; i < length; i++)
            if (a[i] != b[i])
                ret = false;
    }
    else
        ret = (addr == addr2);

    return ret;
}
