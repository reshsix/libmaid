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

extern void
maid_mem_clear(void *addr, const size_t length)
{
    volatile u8 *dest = addr;
    for (size_t i = 0; i < length; i++)
        dest[i] = 0x0;
}

#ifndef NDEBUG
#include <stdio.h>

extern void
maid_mp_debug(const char *name, const u32 *x, const size_t s)
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
maid_mp_add(u32 *out, const u32 *a, const u32 *b,
            const size_t so, const size_t sa, const size_t sb)
{
    volatile u64 carry = 0;

    volatile u32 *dest = out;
    for (size_t i = 0; i < so; i++)
    {
        carry += (i < sa) ? a[i] : 0;
        carry += (i < sb) ? b[i] : 0;

        dest[i] = carry & 0xFFFFFFFF;
        carry   = carry >> 32;
    }

    carry = 0;
}

extern void
maid_mp_sub(u32 *out, const u32 *a, const u32 *b,
            const size_t so, const size_t sa, const size_t sb)
{
    volatile s64 carry = 0;

    volatile u32 *dest = out;
    for (size_t i = 0; i < so; i++)
    {
        carry += (i < sa) ? a[i] : 0;
        carry -= (i < sb) ? b[i] : 0;

        dest[i] = carry & 0xFFFFFFFF;
        carry   = carry >> 32;
    }

    carry = 0;
}

extern void
maid_mp_mul(u32 *restrict out, const u32 *restrict a,
            const u32 *restrict b, const size_t so,
            const size_t sa, const size_t sb)
{
    memset(out, 0, sizeof(u32) * so);

    volatile u64 mul = 0;

    /* Long multiplication, as karatsuba is leaky */
    for (size_t i = 0; i < sa; i++)
    {
        for (size_t j = 0; j < sb; j++)
        {
            mul  = a[i];
            mul *= b[j];

            size_t idx = (i + j);
            if (idx < so)
            {
                maid_mp_add(&(out[idx]), &(out[idx]),
                            (u32*)&mul, so - idx, so - idx, 2);
            }
        }
    }

    mul = 0;
}

extern void
maid_mp_shr(u32 *restrict out, const u32 *restrict a,
            const size_t n, const size_t so, const size_t sa)
{
    memset(out, 0, sizeof(u32) * so);

    size_t x = (n / 8);
    if ((x + 1) < (so * 4))
    {
        if (x < (sa * 4))
        {
            size_t s = (so * 4) - x;
            size_t m = (sa * 4) - x;
            if (m < s)
                s = m;

            memcpy(out, &(((u8*)a)[x]), s);

            u8 nl = n % 32;

            volatile u64 next = 0;
            for (size_t i = 0; i < so; i++)
            {
                next = ((i + 1) < so) ? out[i + 1] : 0x0;
                out[i] = (next << (32 - nl)) | (out[i] >> nl);
            }
            next = 0;
        }
    }
}
