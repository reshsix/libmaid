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

#ifndef NDEBUG
#include <stdio.h>

extern void
maid_mp_debug(const char *name, const u32 *x, size_t s)
{
    fprintf(stderr, "%s:\n", name);
    for (size_t i = 0; i < s; i++)
    {
        if (i && i % 4 == 0)
            fprintf(stderr, "\n");

        fprintf(stderr, "%08x", x[s - 1 - i]);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n\n");
}
#endif

extern void
maid_mp_clr(size_t words, u32 *a)
{
    if (a)
        maid_mem_clear(a, words * sizeof(u32));
}

extern void
maid_mp_mov(size_t words, u32 *a, const u32 *b)
{
    if (a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] = (b) ? b[i] : 0x0;
    }
}

extern void
maid_mp_add(size_t words, u32 *a, const u32 *b)
{
    if (a)
    {
        volatile u64 carry = 0;

        for (size_t i = 0; i < words; i++)
        {
            carry += a[i];
            carry += (b) ? b[i] : 0x0;

            a[i] = carry & 0xFFFFFFFF;
            carry >>= 32;
        }

        carry = 0;
    }
}

extern void
maid_mp_sub(size_t words, u32 *a, const u32 *b)
{
    if (a)
    {
        volatile s64 carry = 0;

        for (size_t i = 0; i < words; i++)
        {
            carry += a[i];
            carry -= (b) ? b[i] : 0x0;

            a[i] = carry & 0xFFFFFFFF;
            carry >>= 32;
        }

        carry = 0;
    }
}

extern void
maid_mp_shl(size_t words, u32 *a, u64 shift)
{
    if (words && a)
    {
        const u64 c = shift / 32;
        const u8  d = shift % 32;
        const u32 m = (1 << (32 - d)) - 1;

        volatile u32 x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            size_t ii = words - i - 1;
            x[0] = (ii >= c) ? a[ii - c - 0] : 0x0;
            x[1] = (ii >  c) ? a[ii - c - 1] : 0x0;
            a[ii] = ((x[0] & m) << d) | ((x[1] & ~m) >> (32 - d));
        }
        x[0] = 0;
        x[1] = 0;
    }
}

extern void
maid_mp_shr(size_t words, u32 *a, u64 shift)
{
    if (words && a)
    {
        const u64 c = shift / 32;
        const u8  d = shift % 32;
        const u32 m = (1 << d) - 1;

        volatile u32 x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            x[0] = ((i + 0) < words) ? a[i + c + 0] : 0x0;
            x[1] = ((i + 1) < words) ? a[i + c + 1] : 0x0;
            a[i] = (x[0] & ~m) >> d | (x[1] & m) << (32 - d);
        }
        x[0] = 0;
        x[1] = 0;
    }
}

extern void
maid_mp_mul(size_t words, u32 *a, const u32 *b, u32 *tmp)
{
    if (words && a && tmp)
    {
        maid_mp_mov(words, tmp, a);
        maid_mp_clr(words, a);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : 0x0) & (1 << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : 0x0) & (1 << d);

            if (bit)
                maid_mp_add(words, a, tmp);
            else
                maid_mp_add(words, a, NULL);

            maid_mp_shl(words, tmp, i <= msb);
        }

        msb = 0;
        bit = false;
    }
}
