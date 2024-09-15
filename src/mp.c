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

#include <stdio.h>
#include <string.h>

#include <maid/mem.h>

extern void
maid_mp_debug(size_t words, const char *name, const u32 *a)
{
    fprintf(stderr, "%s:\n", name);
    for (size_t i = 0; i < words; i++)
    {
        if (i && i % 4 == 0)
            fprintf(stderr, "\n");

        fprintf(stderr, "%08x", a[words - 1 - i]);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n\n");
}

extern void
maid_mp_read(size_t words, u32 *a, const u8 *addr, bool big)
{
    for (size_t i = 0; i < words; i++)
    {
        u32 val = maid_mem_read(addr, (!big) ? i : words - i - 1,
                                sizeof(u32), big);
        maid_mem_write(a, i, sizeof(u32), false, val);
    }
}

extern void
maid_mp_write(size_t words, const u32 *a, u8 *addr, bool big)
{
    for (size_t i = 0; i < words; i++)
    {
        maid_mem_write(addr, (!big) ? i : words - i - 1,
                       sizeof(u32), big, a[i]);
    }
}

extern s8
maid_mp_cmp(size_t words, const u32 *a, const u32 *b)
{
    s8 ret = 0;

    if (a)
    {
        volatile u32 x, y;
        volatile s8 none = 0;
        for (size_t i = 0; i < words; i++)
        {
            size_t ii = words - i - 1;

            x = (a ? a[ii] : 0x0);
            y = (b ? b[ii] : 0x0);

            volatile s8 val = 0;
            if (x > y)
                val = -1;
            else if (x < y)
                val = 1;
            else
                val = 0;

            if (!ret)
                ret = val;
            else
                none = val;

            val = 0;
        }
        x = 0;
        y = 0;
        none = 0;
        (void)none;
    }

    return ret;
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
        const u8 id = (32 - d) % 32;
        const u32 m = d ? (1UL << id) - 1UL : 0xffffffff;

        volatile u32 x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            size_t ii = words - i - 1;
            x[0] = (ii >= c) ? a[ii - c - 0] : 0x0;
            x[1] = (ii >  c) ? a[ii - c - 1] : 0x0;
            a[ii] = ((x[0] & m) << d) | ((x[1] & ~m) >> id);
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
        const u8 id = (32 - d) % 32;
        const u32 m = (1 << d) - 1;

        volatile u32 x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            x[0] = ((i + c + 0) < words) ? a[i + c + 0] : 0x0;
            x[1] = ((i + c + 1) < words) ? a[i + c + 1] : 0x0;
            a[i] = (x[0] & ~m) >> d | (x[1] & m) << id;
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
        maid_mp_mov(words, a, NULL);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : ((i == 0) ? 0x1 : 0x0)) & (1 << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : ((i == 0) ? 0x1 : 0x0)) & (1 << d);

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

extern void
maid_mp_div(size_t words, u32 *a, const u32 *b, u32 *tmp)
{
    if (words && a && tmp)
    {
        u32 *tmp2 = &(tmp[words]);
        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t ii = (words * 32) - i - 1;

            maid_mp_mov(words, tmp2, tmp);
            maid_mp_shr(words, tmp2, ii);

            volatile bool sub = true;
            if (b)
            {
                sub = (maid_mp_cmp(words, b, tmp2) >= 0);
                maid_mp_mov(words, tmp2, b);
            }
            else
            {
                /* Does the same stuff, except with b = 1 */
                volatile bool none = false;
                for (size_t i = 0; i < words; i++)
                {
                    size_t ii = words - i - 1;
                    if (tmp2[ii] < ((ii == 0) ? 0x01 : 0x00))
                    {
                        if (sub)
                            sub = false;
                        else
                            none = false;
                    }
                }
                (void)none;

                for (size_t i = 0; i < words; i++)
                    tmp2[i] = (i == 0) ? 0x01 : 0x00;
            }

            maid_mp_shl(words, tmp2, ii);
            maid_mp_sub(words, tmp, (sub) ? tmp2 : NULL);

            size_t c = ii / 32;
            u8     d = ii % 32;

            volatile u32 value = (sub) ? (1 << d) : 0;
            a[c] |= value;
            value = 0;

            sub = false;
        }
    }
}

extern void
maid_mp_mod(size_t words, u32 *a, const u32 *b, u32 *tmp)
{
    if (words && a && tmp)
    {
        u32 *tmp2 = &(tmp[words]);

        maid_mp_mov(words, tmp, a);
        maid_mp_div(words, tmp, b, tmp2);
        maid_mp_mul(words, tmp, b, tmp2);
        maid_mp_sub(words, a, tmp);
    }
}

extern void
maid_mp_exp(size_t words, u32 *a, const u32 *b, u32 *tmp)
{
    if (words && a && tmp)
    {
        u32 *tmp2 = &(tmp[words]);
        u32 *tmp3 = &(tmp[words * 2]);

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;

        maid_mp_mov(words, tmp2, NULL);
        maid_mp_mov(words, tmp3, NULL);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1 << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t ii = (words * 32) - i - 1;

            size_t c = ii / 32;
            u8     d = ii % 32;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1 << d);

            maid_mp_mov(words, tmp2, a);
            if (msb && i == 0)
                maid_mp_mul(words, a, tmp, tmp3);
            else if (msb && ii < (msb - 1))
                maid_mp_mul(words, a, tmp2, tmp3);
            else
                maid_mp_mul(words, a, NULL, tmp3);

            if (bit)
                maid_mp_mul(words, a, tmp, tmp3);
            else
                maid_mp_mul(words, a, NULL, tmp3);
        }

        msb = 0;
        bit = false;
    }
}

extern void
maid_mp_div2(size_t words, u32 *a, u32 *rem, const u32 *b, u32 *tmp)
{
    if (words && a && rem && tmp)
    {
        u32 *tmp2 = &(tmp[words]);

        maid_mp_mov(words, rem, a);
        maid_mp_div(words, a, b, tmp2);
        maid_mp_mov(words, tmp, a);

        maid_mp_mul(words, tmp, b, tmp2);
        maid_mp_sub(words, rem, tmp);
    }
}

extern void
maid_mp_egcd(size_t words, u32 *a, u32 *b, u32 *gcd, u32 *tmp)
{
    if (words && a && b && gcd && tmp)
    {
        u32 *or = a;
        u32 *r  = b;

        u32 *os = &(tmp[words * 0]);
        u32 *s  = &(tmp[words * 1]);
        u32 *ot = &(tmp[words * 2]);
        u32 *t  = &(tmp[words * 3]);

        maid_mp_mov(words, os, NULL);
        maid_mp_mov(words, s,  NULL);
        maid_mp_mov(words, ot, NULL);
        maid_mp_mov(words, t,  NULL);
        os[0] = 0x1;
        t[0] = 0x1;

        u32 *quot  = &(tmp[words * 4]);
        u32 *quot2 = &(tmp[words * 5]);
        u32 *tmp2  = &(tmp[words * 6]);

        for (size_t i = 0; i < words * 32; i++)
        {
            maid_mp_mov(words, quot, or);
            maid_mp_div(words, quot, r, tmp2);

            if (maid_mp_cmp(words, r, NULL) != 0)
            {
                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, r, tmp2);
                maid_mp_sub(words, or, quot2);

                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, s, tmp2);
                maid_mp_sub(words, os, quot2);

                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, t, tmp2);
                maid_mp_sub(words, ot, quot2);

                maid_mp_mov(words, quot2, r);
                maid_mp_mov(words, r, or);
                maid_mp_mov(words, or, quot2);

                maid_mp_mov(words, quot2, s);
                maid_mp_mov(words, s, os);
                maid_mp_mov(words, os, quot2);

                maid_mp_mov(words, quot2, t);
                maid_mp_mov(words, t, ot);
                maid_mp_mov(words, ot, quot2);
            }
            else
            {
                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, r, tmp2);
                maid_mp_sub(words, or, NULL);

                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, s, tmp2);
                maid_mp_sub(words, os, NULL);

                maid_mp_mov(words, quot2, quot);
                maid_mp_mul(words, quot2, t, tmp2);
                maid_mp_sub(words, ot, NULL);

                maid_mp_mov(words, quot2, or);
                maid_mp_mov(words, or, r);
                maid_mp_mov(words, or, quot2);

                maid_mp_mov(words, quot2, os);
                maid_mp_mov(words, os, s);
                maid_mp_mov(words, os, quot2);

                maid_mp_mov(words, quot2, ot);
                maid_mp_mov(words, ot, t);
                maid_mp_mov(words, ot, quot2);
            }
        }

        maid_mp_mov(words, gcd, or);
        maid_mp_mov(words, a,   os);
        maid_mp_mov(words, b,   ot);
    }
}

extern void
maid_mp_mulmod(size_t words, u32 *a, const u32 *b, const u32 *mod, u32 *tmp)
{
    if (words && a && tmp)
    {
        u32 *a2   = &(tmp[words * 0]);
        u32 *b2   = &(tmp[words * 2]);
        u32 *mod2 = &(tmp[words * 4]);
        u32 *tmp2 = &(tmp[words * 6]);

        maid_mp_mov(words, a2,   a);
        maid_mp_mov(words, b2,   b);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mov(words, &(a2[words]),   NULL);
        maid_mp_mov(words, &(b2[words]),   NULL);
        maid_mp_mov(words, &(mod2[words]), NULL);

        if (b)
            maid_mp_mul(words * 2, a2, b2, tmp2);
        else
            maid_mp_mul(words * 2, a2, NULL, tmp2);

        maid_mp_mod(words * 2, a2, mod2, tmp2);
        maid_mp_mov(words, a, a2);
    }
}

extern void
maid_mp_expmod(size_t words, u32 *a, const u32 *b, const u32 *mod, u32 *tmp)
{
    if (words && a && mod && tmp)
    {
        u32 *tmp2 = &(tmp[words]);
        u32 *tmp3 = &(tmp[words * 2]);

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;

        maid_mp_mov(words, tmp2, NULL);
        maid_mp_mov(words, tmp3, NULL);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t c = i / 32;
            u8     d = i % 32;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1 << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * 32; i++)
        {
            size_t ii = (words * 32) - i - 1;

            size_t c = ii / 32;
            u8     d = ii % 32;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1 << d);

            maid_mp_mov(words, tmp2, a);
            if (msb && i == 0)
                maid_mp_mulmod(words, a, tmp, mod, tmp3);
            else if (msb && ii < (msb - 1))
                maid_mp_mulmod(words, a, tmp2, mod, tmp3);
            else
                maid_mp_mulmod(words, a, NULL, mod, tmp3);

            if (bit)
                maid_mp_mulmod(words, a, tmp, mod, tmp3);
            else
                maid_mp_mulmod(words, a, NULL, mod, tmp3);
        }

        msb = 0;
        bit = false;
    }
}
