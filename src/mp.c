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

        fprintf(stderr, "%08x", (a) ? a[words - 1 - i] : 0x0);
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
maid_mp_sal(size_t words, u32 *a, u64 shift)
{
    maid_mp_shr(words, a, shift);
}

extern void
maid_mp_sar(size_t words, u32 *a, u64 shift)
{
    if (words && a)
    {
        volatile u32 fill = (a[words - 1] & (1 << 31)) ? 0xFFFFFFFF: 0x00;

        const u64 c = shift / 32;
        const u8  d = shift % 32;
        const u8 id = (32 - d) % 32;
        const u32 m = (1 << d) - 1;

        volatile u32 x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            x[0] = ((i + c + 0) < words) ? a[i + c + 0] : fill;
            x[1] = ((i + c + 1) < words) ? a[i + c + 1] : fill;
            a[i] = (x[0] & ~m) >> d | (x[1] & m) << id;
        }
        x[0] = 0;
        x[1] = 0;

        fill = 0x0;
    }
}

extern void
maid_mp_mul(size_t words, u32 *a, const u32 *b, u32 *tmp)
{
    if (words && a && tmp)
    {
        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);

        volatile u64 mul = 0;
        for (size_t i = 0; i < words; i++)
        {
            for (size_t j = 0; j < words; j++)
            {
                size_t idx = (i + j);
                mul  = tmp[i];
                mul *= (b) ? b[j] : (j == 0);

                if (idx < words)
                {
                    volatile u64 carry = 0;
                    for (size_t k = idx; k < words; k++)
                    {
                        carry += a[k];
                        if (k == idx)
                            carry += mul & 0xFFFFFFFF;
                        else if (k == (idx + 1))
                            carry += mul >> 32;

                        a[k] = carry & 0xFFFFFFFF;
                        carry >>= 32;
                    }
                    carry = 0;
                }
            }
        }
        mul = 0;
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
maid_mp_mulmod(size_t words, u32 *a, const u32 *b, const u32 *mod, u32 *tmp)
{
    if (words && a && mod && tmp)
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

static void
maid_mp_egcd(size_t words, u32 *a, u32 *b, u32 *gcd,
             bool *xs, bool *ys, u32 *tmp)
{
    /* tmp[] = (words * 18) */

    if (words && a && b && gcd && tmp)
    {
        /* Crude approximation of nth fibbonaci < 2^(words * 32)
         * Very rounded up to avoid skipping a last step */
        const size_t steps = ((((words * 32) + 2) * 145)/ 100) + 1;

        u32 *a2   = &(tmp[words *  0]);
        u32 *b2   = &(tmp[words *  2]);
        u32 *u    = &(tmp[words *  4]);
        u32 *v    = &(tmp[words *  6]);
        u32 *s    = &(tmp[words *  8]);
        u32 *t    = &(tmp[words * 10]);
        u32 *oa   = &(tmp[words * 12]);
        u32 *ob   = &(tmp[words * 14]);
        u32 *tmp2 = &(tmp[words * 16]);

        volatile size_t r = 0;
        for (size_t i = 0; i < steps; i++)
        {
            if (((a[0] & 0x1) | (b[0] & 0x1)) == 0x0)
            {
                maid_mp_sar(words, a, 1);
                maid_mp_sar(words, b, 1);
                r += 1;
            }
            else
            {
                maid_mp_sar(words, a, 0);
                maid_mp_sar(words, b, 0);
                r += 0;
            }
        }

        maid_mp_mov(words, &(oa[words]), NULL);
        maid_mp_mov(words, &(ob[words]), NULL);
        maid_mp_mov(words, oa, a);
        maid_mp_mov(words, ob, b);

        maid_mp_mov(words, &(a2[words]), NULL);
        maid_mp_mov(words, &(b2[words]), NULL);
        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b2, b);
        u32 *x = a;
        u32 *y = b;
        a = a2;
        b = b2;

        maid_mp_mov(words * 2, u, NULL);
        maid_mp_mov(words * 2, v, NULL);
        maid_mp_mov(words * 2, s, NULL);
        maid_mp_mov(words * 2, t, NULL);
        u[0] = 0x1;
        t[0] = 0x1;

        for (size_t i = 0; i < steps; i++)
        {
            bool even = ((a[0] & 0x1) == 0);

            maid_mp_sar(words * 2, a, (even) ? 1 : 0);
            if (((u[0] & 0x1) | (v[0] & 0x1)) == 0)
            {
                maid_mp_add(words * 2, u, NULL);
                maid_mp_sub(words * 2, v, NULL);
            }
            else
            {
                maid_mp_add(words * 2, u, (even) ? ob : NULL);
                maid_mp_sub(words * 2, v, (even) ? oa : NULL);
            }
            maid_mp_sar(words * 2, u, (even) ? 1 : 0);
            maid_mp_sar(words * 2, v, (even) ? 1 : 0);
        }

        for (size_t i = 0; i < steps * 2; i++)
        {
            s8 cmp = maid_mp_cmp(words, a, b);
            bool diff   = (cmp != 0);
            bool even   = ((b[0] & 0x1) == 0);
            bool both   = (((s[0] & 0x1) | (t[0] & 0x1)) == 0);
            bool larger = (cmp < 0);

            maid_mp_sar(words * 2, b, (diff & even) ? 1 : 0);
            maid_mp_add(words * 2, s, (diff & even & !both) ? ob : NULL);
            maid_mp_sub(words * 2, t, (diff & even & !both) ? oa : NULL);
            maid_mp_sar(words * 2, s, (diff & even) ? 1 : 0);
            maid_mp_sar(words * 2, t, (diff & even) ? 1 : 0);

            maid_mp_mov(words * 2, tmp2, a);
            maid_mp_mov(words * 2, a, b);
            maid_mp_mov(words * 2, (diff & !even & larger) ? b : a, tmp2);
            maid_mp_mov(words * 2, tmp2, u);
            maid_mp_mov(words * 2, u, s);
            maid_mp_mov(words * 2, (diff & !even & larger) ? s : u, tmp2);
            maid_mp_mov(words * 2, tmp2, v);
            maid_mp_mov(words * 2, v, t);
            maid_mp_mov(words * 2, (diff & !even & larger) ? t : v, tmp2);

            maid_mp_sub(words * 2, b, (diff & !even & !larger) ? a : NULL);
            maid_mp_sub(words * 2, s, (diff & !even & !larger) ? u : NULL);
            maid_mp_sub(words * 2, t, (diff & !even & !larger) ? v : NULL);
        }

        maid_mp_mov(words, gcd, NULL);
        gcd[0] = 0x1;
        maid_mp_shl(words, gcd, r);
        maid_mp_mul(words, gcd, a, tmp2);

        maid_mp_mov(words, x, s);
        maid_mp_mov(words, y, t);

        *xs = s[(words * 2) - 1] & (1 << 31);
        *ys = t[(words * 2) - 1] & (1 << 31);

        r = 0;
    }
}

extern bool
maid_mp_invmod(size_t words, u32 *a, const u32 *mod, u32 *tmp)
{
    bool ret = false;

    if (words && a && mod && tmp)
    {
        volatile bool xs = false;
        volatile bool ys = false;

        u32 *a2   = &(tmp[words * 0]);
        u32 *b    = &(tmp[words * 1]);
        u32 *gcd  = &(tmp[words * 2]);
        u32 *tmp2 = &(tmp[words * 3]);

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b, mod);
        maid_mp_egcd(words, a2, b, gcd, (bool*)&xs, (bool*)&ys, tmp2);

        maid_mp_mov(words, b, NULL);
        b[0] = 0x1;
        if (maid_mp_cmp(words, gcd, b) == 0)
        {
           ret = true;
           maid_mp_mov(words, a, a2);
           maid_mp_add(words, a, xs ? mod : NULL);
        }

        xs = false;
        ys = false;
    }

    return ret;
}

static void
maid_mp_mont_mulmod(size_t words, u32 *ma, const u32 *mb,
                    const u32 *mod, const u32 *imod, u32 *tmp)
{
    /* tmp[] = (words * 14) */

    if (words && ma && mod && tmp)
    {
        u32 *a2    = &(tmp[words * 0]);
        u32 *b2    = &(tmp[words * 3]);
        u32 *mod2  = &(tmp[words * 5]);
        u32 *imod2 = &(tmp[words * 7]);
        u32 *acc   = &(tmp[words * 9]);
        u32 *tmp2  = &(tmp[words * 12]);

        maid_mp_mov(words, a2,   ma);
        maid_mp_mov(words, b2,   mb);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mov(words + 1, &(a2[words]),   NULL);
        maid_mp_mov(words,     &(b2[words]),   NULL);
        maid_mp_mov(words,     &(mod2[words]), NULL);

        maid_mp_mul(words * 2, a2, (mb) ? b2 : NULL, tmp2);

        maid_mp_mov(words, &(imod2[words]), NULL);
        maid_mp_mov(words, imod2, imod);

        maid_mp_mov(words * 2, acc, imod2);
        acc[words * 2] = 0x0;

        maid_mp_mul(words * 1, acc, a2, tmp2);
        maid_mp_mov(words + 1, &(acc[words]), NULL);
        maid_mp_mul(words * 2, acc, mod2, tmp2);
        maid_mp_add((words * 2) + 1, acc, a2);
        maid_mp_shr((words * 2) + 1, acc, words * 32);

        if (maid_mp_cmp(words * 2, acc, mod2) < 0)
            maid_mp_sub(words * 2, acc, mod2);
        else
            maid_mp_sub(words * 2, acc, NULL);

        maid_mp_mov(words, ma, acc);
    }
}

static void
maid_mp_mont_in(size_t words, u32 *a, const u32 *mod, u32 *tmp)
{
    /* tmp[] = words * 30 */

    if (words && a && mod && tmp)
    {
        u32 *a2   = &(tmp[words * 0]);
        u32 *mod2 = &(tmp[words * 2]);
        u32 *rmod = &(tmp[words * 4]);
        u32 *tmp2 = &(tmp[words * 6]);

        maid_mp_mov(words * 2, rmod, NULL);
        rmod[words] = 0x1;

        maid_mp_mov(words, &(a2[words]),   NULL);
        maid_mp_mov(words, &(mod2[words]), NULL);
        maid_mp_mov(words, a2,   a);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mulmod(words * 2, a2, rmod, mod2, tmp2);
        maid_mp_mov(words, a, a2);
    }
}

static void
maid_mp_mont_out(size_t words, u32 *a, const u32 *mod,
                 const u32 *imod, u32 *tmp)
{
    /* tmp[] = (words * 14) */

    return maid_mp_mont_mulmod(words, a, NULL, mod, imod, tmp);
}

extern void
maid_mp_expmod2(size_t words, u32 *a, const u32 *b, const u32 *mod,
                u32 *tmp, bool constant)
{
    if (words && a && mod && tmp)
    {
        u32 *org  = &(tmp[words * 0]);
        u32 *imod = &(tmp[words * 1]);
        u32 *acc  = &(tmp[words * 3]);
        u32 *one  = &(tmp[words * 5]);
        u32 *tmp2 = &(tmp[words * 7]);

        u32 *rmod = acc;
        maid_mp_mov(words * 2, rmod, NULL);
        rmod[words] = 0x1;

        maid_mp_mov(words, &(imod[words]), NULL);
        maid_mp_mov(words, imod, mod);
        maid_mp_invmod(words * 2, imod, rmod, tmp2);

        maid_mp_mov(words * 2, acc, imod);
        maid_mp_mov(words * 2, imod, NULL);
        maid_mp_sub(words * 2, imod, acc);
        maid_mp_mov(words * 2, acc, NULL);

        maid_mp_mont_in(words, a, mod, tmp2);
        maid_mp_mov(words, org, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;
        maid_mp_mont_in(words, a, mod, tmp2);
        maid_mp_mov(words, one, a);

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

            maid_mp_mov(words, acc, a);
            if (msb && i == 0)
                maid_mp_mont_mulmod(words, a, org, mod, imod, tmp2);
            else if (msb && ii < (msb - 1))
                maid_mp_mont_mulmod(words, a, acc, mod, imod, tmp2);
            else if (constant)
                maid_mp_mont_mulmod(words, a, one, mod, imod, tmp2);

            if (bit)
                maid_mp_mont_mulmod(words, a, org, mod, imod, tmp2);
            else if (constant)
                maid_mp_mont_mulmod(words, a, one, mod, imod, tmp2);
        }

        msb = 0;
        bit = false;

        maid_mp_mont_out(words, a, mod, imod, tmp2);
    }
}
