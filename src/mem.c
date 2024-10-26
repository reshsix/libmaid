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

extern size_t
maid_mem_import(void *addr, size_t limit, const char *input, size_t length)
{
    size_t ret = 0;

    char table[256] = {0};
    memset(table, 0xFF, sizeof(table));

    table['='] = 0;
    for (int i = 0; i < 26; i++)
        table['A' + i] = i;
    for (int i = 0; i < 26; i++)
        table['a' + i] = 26 + i;
    for (int i = 0; i < 10; i++)
        table['0' + i] = 52 + i;
    table['+'] = 62;
    table['/'] = 63;

    /* Won't read if there's any error */
    volatile bool error = (length % 4 != 0);
    for (size_t i = 0; i < length; i++)
    {
        char c = input[i];

        u8 t = table[(int)c];
        /* Invalid character */
        if (t == 0xFF)
           error = true;
        /* Padding not at the end */
        if (t == 0x00 && !(i == length - 1 || i == length - 2))
           error = true;
        /* Padding on last but one, but not on last */
        if (t == 0x00 && i == length - 2 && table[(int)input[i + 1]] != 0x00)
           error = true;
    }

    /* But will pretend to, avoiding timing attacks */
    volatile u8 *a = addr;
    volatile u8 zero = 0;
    while (length && limit)
    {
        size_t l  = (length < 4) ? length : 4;
        size_t l2 = (limit  < 3) ? limit  : 3;

        volatile u8 sext[4] = {0};
        for (size_t i = 0; i < 4; i++)
            sext[i] = (l > i) ? table[(int)input[i]] : 0;

        a[0] = (!error) ? (sext[0] << 2 |  sext[1] >> 4)     : zero;
        a[1] = (!error) ? (sext[1] << 4 |  sext[2] >> 2)     : zero;
        a[2] = (!error) ? (sext[2] << 6 | (sext[3] &  0x3F)) : zero;

        input = &(input[4]);
        length -= l;

        a = &(a[3]);
        limit -= l2;

        ret += (!error) ? l : zero;
        for (size_t i = 0; i < sizeof(sext); i++)
            sext[i] = 0x00;
    }
    error = false;

    return ret;
}

extern size_t
maid_mem_export(const void *addr, size_t length, char *output, size_t limit)
{
    size_t ret = 0;

    const char table[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const u8 *a = addr;
    while (length && limit)
    {
        size_t l  = (length < 3) ? length : 3;
        size_t l2 = (limit  < 4) ? limit  : 4;

        u8 sext[4] = {0};
        sext[0] = a[0] >> 2;
        sext[1] = a[0] << 4 & 0x3F;
        sext[1] |= (l > 1) ? (a[1] >> 4) : 0;
        sext[2] =  (l > 1) ? (a[1] << 2 & 0x3F) : 0;
        sext[2] |= (l > 2) ? (a[2] >> 6) : 0;
        sext[3] =  (l > 2) ? (a[2] & 0x3F) : 0;

        output[0] = table[sext[0]];
        if (l2 > 1) output[1] = table[sext[1]];
        if (l2 > 2) output[2] = (l > 1) ? table[sext[2]] : '=';
        if (l2 > 3) output[3] = (l > 2) ? table[sext[3]] : '=';

        a = &(a[3]);
        length -= l;

        output = &(output[4]);
        limit -= l2;

        ret += l2;
        maid_mem_clear(sext, sizeof(sext));
    }

    return ret;
}
