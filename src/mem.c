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

#include <maid/mem.h>

#include <internal/types.h>

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
maid_mem_cmp(const void *addr, const void *addr2, size_t length)
{
    volatile bool ret = true;

    if (addr && addr2)
    {
        const volatile u8 *a = addr;
        const volatile u8 *b = addr2;
        for (size_t i = 0; i < length; i++)
            if (a[i] != b[i])
                ret = false;
    }
    else
        ret = (addr == addr2);

    return ret;
}

static size_t
base16_import(void *addr, size_t limit,
              const char *input, size_t length, bool upper)
{
    size_t ret = 0;

    volatile u8 table[256] = {0};
    memset((u8*)table, 0xFF, sizeof(table));

    for (int i = 0; i < 10; i++)
        table['0' + i] = i;
    for (int i = 0; i < 6; i++)
        table[((upper) ? 'A' : 'a') + i] = 10 + i;

    /* Won't read if there's any error */
    volatile bool error = (length % 2 != 0);
    for (size_t i = 0; i < length; i++)
    {
        char c = input[i];

        u8 t = table[(int)c];
        /* Invalid character */
        if (t == 0xFF)
           error = true;
    }

    /* But will pretend to, avoiding timing attacks */
    volatile u8 *a = addr;
    volatile u8 zero = 0;
    while (length && limit)
    {
        size_t l  = (length < 2) ? length : 2;
        size_t l2 = (limit  < 1) ? limit  : 1;

        volatile u8 digit[2] = {0};
        for (size_t i = 0; i < 2; i++)
            digit[i] = (l > i) ? table[(int)input[i]] : 0;

        a[0] = (!error) ? (digit[0] << 4 | digit[1]) : zero;

        input = &(input[2]);
        length -= l;

        a = &(a[1]);
        limit -= l2;

        ret += (!error) ? l : zero;
        for (size_t i = 0; i < sizeof(digit); i++)
            digit[i] = 0x00;
    }
    error = false;

    return ret;
}

static size_t
base16_export(const void *addr, size_t length,
              char *output, size_t limit, bool upper)
{
    size_t ret = 0;

    const char chars [16] = "0123456789abcdef";
    const char chars2[16] = "0123456789ABCDEF";
    const char *table = (upper) ? chars2 : chars;
    if (limit % 2 != 0)
        limit -= limit % 2;

    const u8 *a = addr;
    while (length && limit)
    {
        size_t l  = (length < 1) ? length : 1;
        size_t l2 = (limit  < 2) ? limit  : 2;

        output[0] = table[a[0] >>  4];
        output[1] = table[a[0] & 0xF];

        a = &(a[1]);
        length -= l;

        output = &(output[2]);
        limit -= l2;

        ret += l2;
    }

    return ret;
}

static size_t
base32_import(void *addr, size_t limit,
              const char *input, size_t length, bool hex)
{
    size_t ret = 0;

    volatile u8 table[256] = {0};
    memset((u8*)table, 0xFF, sizeof(table));

    if (!hex)
    {
        for (int i = 0; i < 26; i++)
            table['A' + i] = i;
        for (int i = 0; i < 6; i++)
            table['2' + i] = 26 + i;
    }
    else
    {
        for (int i = 0; i < 10; i++)
            table['0' + i] = i;
        for (int i = 0; i < 22; i++)
            table['A' + i] = 10 + i;
    }

    /* Won't read if there's any error */
    table['='] = 0xFE;
    volatile bool pad = false;
    volatile bool error = (length % 8 != 0);
    for (size_t i = 0; i < length; i++)
    {
        char c = input[i];

        u8 t = table[(int)c];
        /* Invalid character */
        if (t == 0xFF)
           error = true;
        if (t == 0xFE)
        {
            /* Padding not at the end */
            if (i < length - 6)
               error = true;
            else
            {
                /* Padding starts in the wrong byte */
                if (!pad && (i == length - 2 || i == length - 5))
                   error = true;
            }
            pad = true;
        }
        else if (pad)
        {
            /* Padding interrupted */
            error = true;
        }
    }
    pad = false;

    /* But will pretend to, avoiding timing attacks */
    table['='] = 0x00;
    volatile u8 *a = addr;
    volatile u8 z = 0;
    while (length && limit)
    {
        size_t l  = (length < 8) ? length : 8;
        size_t l2 = (limit  < 5) ? limit  : 5;

        volatile u8 quint[8] = {0};
        for (size_t i = 0; i < 8; i++)
            quint[i] = (l > i) ? table[(int)input[i]] : 0;

        a[0] = (!error) ? (quint[0] << 3 | quint[1] >> 2) : z;
        a[1] = (!error) ? (quint[1] << 6 | quint[2] << 1 | quint[3] >> 4) : z;
        a[2] = (!error) ? (quint[3] << 4 | quint[4] >> 1) : z;
        a[3] = (!error) ? (quint[4] << 7 | quint[5] << 2 | quint[6] >> 3) : z;
        a[4] = (!error) ? (quint[6] << 5 | quint[7]) : z;

        input = &(input[8]);
        length -= l;

        a = &(a[5]);
        limit -= l2;

        ret += (!error) ? l : z;
        for (size_t i = 0; i < sizeof(quint); i++)
            quint[i] = 0x00;
    }
    error = false;

    return ret;
}

static size_t
base32_export(const void *addr, size_t length,
              char *output, size_t limit, bool hex)
{
    size_t ret = 0;

    const char chars [32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const char chars2[32] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const char *table = (hex) ? chars2 : chars;

    if (limit % 8 != 0)
        limit -= limit % 8;

    const u8 *a = addr;
    while (length && limit)
    {
        size_t l  = (length < 5) ? length : 5;
        size_t l2 = (limit  < 8) ? limit  : 8;

        u8 quint[8] = {0};
        quint[0] =  (a[0] >> 3);
        quint[1] =  (a[0] << 2) & 0x1C;
        quint[1] |= (l > 1) ? (a[1] >> 6) : 0;
        quint[2] =  (l > 1) ? (a[1] >> 1) & 0x1F : 0;
        quint[3] =  (l > 1) ? (a[1] << 4) & 0x10 : 0;
        quint[3] |= (l > 2) ? (a[2] >> 4) & 0x0F : 0;
        quint[4] =  (l > 2) ? (a[2] << 1) & 0x1E : 0;
        quint[4] |= (l > 3) ? (a[3] >> 7) & 0x01 : 0;
        quint[5] =  (l > 3) ? (a[3] >> 2) & 0x1F : 0;
        quint[6] =  (l > 3) ? (a[3] << 3) & 0x18 : 0;
        quint[6] |= (l > 4) ? (a[4] >> 5) & 0x07 : 0;
        quint[7] =  (l > 4) ? (a[4] & 0x1F) : 0;

        output[0] = table[quint[0]];
        if (l2 > 1) output[1] = table[quint[1]];
        if (l2 > 2) output[2] = (l > 1) ? table[quint[2]] : '=';
        if (l2 > 3) output[3] = (l > 1) ? table[quint[3]] : '=';
        if (l2 > 4) output[4] = (l > 2) ? table[quint[4]] : '=';
        if (l2 > 5) output[5] = (l > 3) ? table[quint[5]] : '=';
        if (l2 > 6) output[6] = (l > 3) ? table[quint[6]] : '=';
        if (l2 > 7) output[7] = (l > 4) ? table[quint[7]] : '=';

        a = &(a[5]);
        length -= l;

        output = &(output[8]);
        limit -= l2;

        ret += l2;
        maid_mem_clear(quint, sizeof(quint));
    }

    return ret;
}

static size_t
base64_import(void *addr, size_t limit,
              const char *input, size_t length, bool url)
{
    size_t ret = 0;

    volatile u8 table[256] = {0};
    memset((u8*)table, 0xFF, sizeof(table));

    for (int i = 0; i < 26; i++)
        table['A' + i] = i;
    for (int i = 0; i < 26; i++)
        table['a' + i] = 26 + i;
    for (int i = 0; i < 10; i++)
        table['0' + i] = 52 + i;
    table[(url) ? '-' : '+'] = 62;
    table[(url) ? '_' : '/'] = 63;

    /* Won't read if there's any error */
    table['='] = 0xFE;
    volatile bool error = (length % 4 != 0);
    for (size_t i = 0; i < length; i++)
    {
        char c = input[i];

        u8 t = table[(int)c];
        /* Invalid character */
        if (t == 0xFF)
           error = true;
        /* Padding not at the end */
        if (t == 0xFE && !(i == length - 1 || i == length - 2))
           error = true;
        /* Padding on last but one, but not on last */
        if (t == 0xFE && i == length - 2 && table[(int)input[i + 1]] != 0xFE)
           error = true;
    }

    /* But will pretend to, avoiding timing attacks */
    table['='] = 0x00;
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

static size_t
base64_export(const void *addr, size_t length,
              char *output, size_t limit, bool url)
{
    size_t ret = 0;

    const char chars [64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char chars2[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char *table = (url) ? chars2 : chars;

    if (limit % 4 != 0)
        limit -= limit % 4;

    const u8 *a = addr;
    while (length && limit)
    {
        size_t l  = (length < 3) ? length : 3;
        size_t l2 = (limit  < 4) ? limit  : 4;

        u8 sext[4] = {0};
        sext[0] = a[0] >> 2;
        sext[1] = a[0] << 4 & 0x3F;
        sext[1] |= (l > 1) ? (a[1] >> 4 & 0xFF) : 0;
        sext[2] =  (l > 1) ? (a[1] << 2 & 0x3F) : 0;
        sext[2] |= (l > 2) ? (a[2] >> 6 & 0xFF) : 0;
        sext[3] =  (l > 2) ? (a[2] << 0 & 0x3F) : 0;

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

extern size_t
maid_mem_import(enum maid_mem type, void *addr, size_t limit,
                const char *input, size_t length)
{
    size_t ret = 0;

    switch (type)
    {
        case MAID_BASE16L:
            ret = base16_import(addr, limit, input, length, false);
            break;
        case MAID_BASE16U:
            ret = base16_import(addr, limit, input, length, true);
            break;
        case MAID_BASE32:
            ret = base32_import(addr, limit, input, length, false);
            break;
        case MAID_BASE32HEX:
            ret = base32_import(addr, limit, input, length, true);
            break;
        case MAID_BASE64:
            ret = base64_import(addr, limit, input, length, false);
            break;
        case MAID_BASE64URL:
            ret = base64_import(addr, limit, input, length, true);
            break;
    }

    return ret;
}

extern size_t
maid_mem_export(enum maid_mem type, const void *addr, size_t length,
                char *output, size_t limit)
{
    size_t ret = 0;

    switch (type)
    {
        case MAID_BASE16L:
            ret = base16_export(addr, length, output, limit, false);
            break;
        case MAID_BASE16U:
            ret = base16_export(addr, length, output, limit, true);
            break;
        case MAID_BASE32:
            ret = base32_export(addr, length, output, limit, false);
            break;
        case MAID_BASE32HEX:
            ret = base32_export(addr, length, output, limit, true);
            break;
        case MAID_BASE64:
            ret = base64_export(addr, length, output, limit, false);
            break;
        case MAID_BASE64URL:
            ret = base64_export(addr, length, output, limit, true);
            break;
    }

    return ret;
}
