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
#include <maid/rng.h>

#include <maid/mp.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

const char *maid_mp_fmt    = "%016lx";
const char *maid_mp_fmt_ns = "%lx";
static const size_t maid_mp_bits  = sizeof(maid_mp_word) * 8;
static const size_t maid_mp_bytes = sizeof(maid_mp_word) * 1;
static const maid_mp_word maid_mp_max = -1;

extern void
maid_mp_read(size_t words, maid_mp_word *a, const u8 *addr, bool big)
{
    if (words && a && addr)
    {
        for (size_t i = 0; i < words; i++)
        {
            maid_mp_word val = maid_mem_read(addr, (!big) ? i : words - i - 1,
                                             maid_mp_bytes, big);
            maid_mem_write(a, i, maid_mp_bytes, false, val);
        }
    }
}

extern void
maid_mp_write(size_t words, const maid_mp_word *a, u8 *addr, bool big)
{
    if (words && addr)
    {
        for (size_t i = 0; i < words; i++)
        {
            maid_mem_write(addr, (!big) ? i : words - i - 1,
                           maid_mp_bytes, big, (a) ? a[i] : 0x0);
        }
    }
}

extern void
maid_mp_debug(size_t words, const char *name, const maid_mp_word *a)
{
    if (words && name)
    {
        volatile bool started = false;
        volatile maid_mp_word w = 0;

        fprintf(stderr, "%s = 0x", name);
        for (size_t i = 0; i < words; i++)
        {
            w = ((a) ? a[words - 1 - i] : 0x0);
            if (!started && w == 0 && i != words - 1)
                continue;

            fprintf(stderr, (started) ? maid_mp_fmt : maid_mp_fmt_ns, w);
            started = true;
        }
        fprintf(stderr, "\n");

        w = 0;
        started = false;
    }
}

extern void
maid_mp_not(size_t words, maid_mp_word *a)
{
    if (words && a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] = ~(a[i]);
    }
}

extern void
maid_mp_and(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] &= (b) ? b[i] : maid_mp_max;
    }
}

extern void
maid_mp_orr(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] |= (b) ? b[i] : 0x0;
    }
}

extern void
maid_mp_xor(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] ^= (b) ? b[i] : 0x0;
    }
}

extern s8
maid_mp_cmp(size_t words, const maid_mp_word *a, const maid_mp_word *b)
{
    s8 ret = 0;

    if (words)
    {
        volatile maid_mp_word x, y;
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
maid_mp_mov(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        for (size_t i = 0; i < words; i++)
            a[i] = (b) ? b[i] : 0x0;
    }
}

extern void
maid_mp_swap(size_t words, maid_mp_word *a, maid_mp_word *b, bool swap)
{
    if (words && a && b)
    {
        MAID_ALLOC_MP(mask, 1)
        MAID_ALLOC_MP(tmp,  1)

        /* mask = 0 - bit */
        tmp[0] = swap;
        maid_mp_sub(words, mask, tmp);

        /* tmp = (a ^ b) & mask */
        maid_mp_mov(words, tmp, a);
        maid_mp_xor(words, tmp, b);
        maid_mp_and(words, tmp, mask);

        /* a ^= tmp, b ^= tmp */
        maid_mp_xor(words, a, tmp);
        maid_mp_xor(words, b, tmp);

        MAID_CLEAR_MP(mask)
        MAID_CLEAR_MP(tmp)
    }
}

extern void
maid_mp_add(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        volatile u8 carry = 0;

        for (size_t i = 0; i < words; i++)
        {
            #if defined(__x86_64__) || defined(_M_X64)
            carry = _addcarry_u64(carry, a[i], b ? b[i] : 0,
                                  (unsigned long long *)&(a[i]));
            #else
            volatile maid_mp_word val = (b ? b[i] : 0);

            a[i] += val;
            a[i] += carry;
            carry = (carry) ? (a[i] <= val) : (a[i] < val);

            val = 0;
            #endif
        }

        carry = 0;
    }
}

extern void
maid_mp_sub(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        volatile u8 borrow = 0;

        for (size_t i = 0; i < words; i++)
        {
            #if defined(__x86_64__) || defined(_M_X64)
            borrow = _subborrow_u64(borrow, a[i], b ? b[i] : 0,
                                    (unsigned long long *)&(a[i]));
            #else
            volatile maid_mp_word org = a[i];
            volatile maid_mp_word val = (b ? b[i] : 0);

            a[i] -= val;
            a[i] -= borrow;
            borrow = (borrow) ? (a[i] >= org) : (a[i] > org);

            org = 0;
            val = 0;
            #endif
        }

        borrow = 0;
    }
}

extern void
maid_mp_shl(size_t words, maid_mp_word *a, size_t shift)
{
    if (words && a)
    {
        const       size_t c = shift / maid_mp_bits;
        const          u8  d = shift % maid_mp_bits;
        const          u8 id = (maid_mp_bits - d) % maid_mp_bits;
        const maid_mp_word m = d ? (1ULL << id) - 1 : maid_mp_max;

        maid_mp_word x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            size_t ii = words - i - 1;
            x[0] = (ii >= c) ? a[ii - c - 0] : 0x0;
            x[1] = (ii >  c) ? a[ii - c - 1] : 0x0;
            a[ii] = ((x[0] & m) << d) | ((x[1] & ~m) >> id);
        }
        maid_mem_clear(x, sizeof(x));
    }
}

extern void
maid_mp_shr(size_t words, maid_mp_word *a, size_t shift)
{
    if (words && a)
    {
        const       size_t c = shift / maid_mp_bits;
        const          u8  d = shift % maid_mp_bits;
        const          u8 id = (maid_mp_bits - d) % maid_mp_bits;
        const maid_mp_word m = (1ULL << d) - 1;

        maid_mp_word x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            x[0] = ((i + c + 0) < words) ? a[i + c + 0] : 0x0;
            x[1] = ((i + c + 1) < words) ? a[i + c + 1] : 0x0;
            a[i] = (x[0] & ~m) >> d | (x[1] & m) << id;
        }
        maid_mem_clear(x, sizeof(x));
    }
}

extern void
maid_mp_sal(size_t words, maid_mp_word *a, size_t shift)
{
    maid_mp_shl(words, a, shift);
}

extern void
maid_mp_sar(size_t words, maid_mp_word *a, size_t shift)
{
    if (words && a)
    {
        volatile maid_mp_word fill = (a[words - 1] &
                                      (1ULL << (maid_mp_bits - 1))) ?
                                     maid_mp_max: 0x00;

        const       size_t c = shift / maid_mp_bits;
        const          u8  d = shift % maid_mp_bits;
        const          u8 id = (maid_mp_bits - d) % maid_mp_bits;
        const maid_mp_word m = (1ULL << d) - 1;

        maid_mp_word x[2] = {0};
        for (size_t i = 0; i < words; i++)
        {
            x[0] = ((i + c + 0) < words) ? a[i + c + 0] : fill;
            x[1] = ((i + c + 1) < words) ? a[i + c + 1] : fill;
            a[i] = (x[0] & ~m) >> d | (x[1] & m) << id;
        }
        maid_mem_clear(x, sizeof(x));

        fill = 0x0;
    }
}

static void
maid_mp_mul_long(size_t words, maid_mp_word *a,
                 const maid_mp_word *b, bool halve)
{
    if (words && a)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

        /* Halving optimizes mulmod, no need to consider odd word length */
        size_t words2 = words;
        if (halve)
            words /= 2;

        /* Uses a bit of space to improve calculations */
        MAID_ALLOC_MP(low,  1)
        MAID_ALLOC_MP(high, 1)

        /* Initializes values */
        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);

        for (size_t i = 0; i < words; i++)
        {
            #if defined(__SIZEOF_INT128__)
            for (size_t j = 0; j < words; j++)
            {
                volatile unsigned __int128 x = tmp[i];
                x *= ((b) ? b[j] : (j == 0));

                low[j]  = x;
                high[j] = x >> 64;
            }
            #else
            const size_t       half = maid_mp_bits / 2;
            const maid_mp_word mask = maid_mp_max >> half;

            volatile maid_mp_word x = tmp[i] >> half;
            volatile maid_mp_word y = tmp[i] & mask;
            for (size_t j = 0; j < words; j++)
            {
                volatile maid_mp_word z = ((b) ? b[j] : (j == 0)) >> half;
                volatile maid_mp_word w = ((b) ? b[j] : (j == 0)) & mask;

                /* Does the intermediary multiplications */
                volatile maid_mp_word xz = x * z;
                volatile maid_mp_word xw = x * w;
                volatile maid_mp_word yz = y * z;
                volatile maid_mp_word yw = y * w;

                /* Calculates low part of the words */
                low[j] = yw;

                volatile maid_mp_word org = low[j];
                low[j] += xw << half;
                high[j] = (low[j] < org);

                org      = low[j];
                low[j]  += yz << half;
                high[j] += (low[j] < org);

                /* Calculates high part of the words */
                high[j] += xz;
                high[j] += xw >> half;
                high[j] += yz >> half;
            }
            #endif

            /* Adds words to the total */
            maid_mp_mov(words2, tmp2, NULL);
            for (size_t j = 0; j < words && (i + j) < words2; j++)
            {
                size_t idx = (i + j);
                tmp2[idx]     = low[j];
                tmp2[idx + 1] = high[j];

                volatile u8 carry = 0;
                for (size_t k = idx; k < words2; k++)
                {
                    a[k] += tmp2[k];
                    a[k] += carry;
                    carry = (carry) ? (a[k] <= tmp2[k]) : (a[k] < tmp2[k]);
                }
                carry = 0;
            }
        }

        MAID_CLEAR_MP(tmp);
        MAID_CLEAR_MP(tmp2);

        MAID_CLEAR_MP(low);
        MAID_CLEAR_MP(high);
    }
}

extern void
maid_mp_mul(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    maid_mp_mul_long(words, a, b, false);
}

extern void
maid_mp_div(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);

        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

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
                for (size_t j = 0; j < words; j++)
                {
                    size_t jj = words - j - 1;
                    if (tmp2[jj] < ((jj == 0) ? 0x01 : 0x00))
                    {
                        if (sub)
                            sub = false;
                        else
                            none = false;
                    }
                }
                (void)none;

                for (size_t j = 0; j < words; j++)
                    tmp2[j] = (j == 0) ? 0x01 : 0x00;
            }

            maid_mp_shl(words, tmp2, ii);
            maid_mp_sub(words, tmp, (sub) ? tmp2 : NULL);

            size_t c = ii / maid_mp_bits;
            u8     d = ii % maid_mp_bits;

            volatile maid_mp_word value = (sub) ? (1ULL << d) : 0;
            a[c] |= value;
            value = 0;

            sub = false;
        }

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
    }
}

extern void
maid_mp_mod(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        MAID_ALLOC_MP(tmp, 1)

        maid_mp_mov(words, tmp, a);
        maid_mp_div(words, tmp, b);
        maid_mp_mul(words, tmp, b);
        maid_mp_sub(words, a, tmp);

        MAID_CLEAR_MP(tmp)
    }
}

extern void
maid_mp_exp(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)
        MAID_ALLOC_MP(tmp3, 1)

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;

        maid_mp_mov(words, tmp2, NULL);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t c = i / maid_mp_bits;
            u8     d = i % maid_mp_bits;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

            size_t c = ii / maid_mp_bits;
            u8     d = ii % maid_mp_bits;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);

            maid_mp_mov(words, tmp2, a);

            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));
            maid_mp_mul(words, a, (i == 0) ? tmp : tmp2);
            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));

            maid_mp_swap(words, a, tmp3, !bit);
            maid_mp_mul(words, a, tmp);
            maid_mp_swap(words, a, tmp3, !bit);
        }

        msb = 0;
        bit = false;

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
        MAID_CLEAR_MP(tmp3)
    }
}

extern void
maid_mp_addmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
               const maid_mp_word *mod)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(a2,   2)
        MAID_ALLOC_MP(b2,   2)
        MAID_ALLOC_MP(mod2, 2)

        maid_mp_mov(words, a2,   a);
        maid_mp_mov(words, b2,   b);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mov(words, &(a2[words]),   NULL);
        maid_mp_mov(words, &(b2[words]),   NULL);
        maid_mp_mov(words, &(mod2[words]), NULL);

        maid_mp_add(words + 1, a2, b2);

        maid_mp_mod(words + 1, a2, mod2);
        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(mod2)
    }
}

extern void
maid_mp_submod(size_t words, maid_mp_word *a, const maid_mp_word *b,
               const maid_mp_word *mod)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(buf,  1)
        MAID_ALLOC_MP(buf2, 1)

        maid_mp_mov(words, buf, b);
        maid_mp_mod(words, buf, mod);
        maid_mp_mov(words, buf2, mod);
        maid_mp_sub(words, buf2, buf);

        maid_mp_addmod(words, a, buf2, mod);

        MAID_CLEAR_MP(buf)
        MAID_CLEAR_MP(buf2)
    }
}

extern void
maid_mp_mulmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
               const maid_mp_word *mod)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(a2,   2)
        MAID_ALLOC_MP(b2,   2)
        MAID_ALLOC_MP(mod2, 2)

        maid_mp_mov(words, a2,   a);
        maid_mp_mov(words, b2,   b);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mov(words, &(a2[words]),   NULL);
        maid_mp_mov(words, &(b2[words]),   NULL);
        maid_mp_mov(words, &(mod2[words]), NULL);

        maid_mp_mul_long(words * 2, a2, b2, true);

        maid_mp_mod(words * 2, a2, mod2);
        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(mod2)
    }
}

static void
maid_mp_egcd(size_t words, maid_mp_word *a, maid_mp_word *b,
             maid_mp_word *gcd, bool *xs, bool *ys)
{
    if (words && a && b && gcd)
    {
        /* Crude approximation of nth fibbonaci < 2^(words * maid_mp_bits)
         * Very rounded up to avoid skipping a last step */
        const size_t steps = ((((words * maid_mp_bits) + 2) * 145)/ 100) + 1;

        MAID_ALLOC_MP(a2,  2)
        MAID_ALLOC_MP(b2,  2)
        MAID_ALLOC_MP(u,   2)
        MAID_ALLOC_MP(v,   2)
        MAID_ALLOC_MP(s,   2)
        MAID_ALLOC_MP(t,   2)
        MAID_ALLOC_MP(oa,  2)
        MAID_ALLOC_MP(ob,  2)
        MAID_ALLOC_MP(tmp, 2)

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
        maid_mp_word *x = a;
        maid_mp_word *y = b;
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

            maid_mp_mov(words * 2, tmp, a);
            maid_mp_mov(words * 2, a, b);
            maid_mp_mov(words * 2, (diff & !even & larger) ? b : a, tmp);
            maid_mp_mov(words * 2, tmp, u);
            maid_mp_mov(words * 2, u, s);
            maid_mp_mov(words * 2, (diff & !even & larger) ? s : u, tmp);
            maid_mp_mov(words * 2, tmp, v);
            maid_mp_mov(words * 2, v, t);
            maid_mp_mov(words * 2, (diff & !even & larger) ? t : v, tmp);

            maid_mp_sub(words * 2, b, (diff & !even & !larger) ? a : NULL);
            maid_mp_sub(words * 2, s, (diff & !even & !larger) ? u : NULL);
            maid_mp_sub(words * 2, t, (diff & !even & !larger) ? v : NULL);
        }

        maid_mp_mov(words, gcd, NULL);
        gcd[0] = 0x1;
        maid_mp_shl(words, gcd, r);
        maid_mp_mul(words, gcd, a);

        maid_mp_mov(words, x, s);
        maid_mp_mov(words, y, t);

        *xs = s[(words * 2) - 1] & (1ULL << (maid_mp_bits - 1));
        *ys = t[(words * 2) - 1] & (1ULL << (maid_mp_bits - 1));

        r = 0;

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(u)
        MAID_CLEAR_MP(v)
        MAID_CLEAR_MP(s)
        MAID_CLEAR_MP(t)
        MAID_CLEAR_MP(oa)
        MAID_CLEAR_MP(ob)
        MAID_CLEAR_MP(tmp)
    }
}

extern bool
maid_mp_invmod(size_t words, maid_mp_word *a, const maid_mp_word *mod)
{
    bool ret = false;

    if (words && a && mod)
    {
        volatile bool xs = false;
        volatile bool ys = false;

        MAID_ALLOC_MP(a2,  1)
        MAID_ALLOC_MP(b,   1)
        MAID_ALLOC_MP(gcd, 1)

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b, mod);
        maid_mp_egcd(words, a2, b, gcd, (bool*)&xs, (bool*)&ys);

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

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b)
        MAID_CLEAR_MP(gcd)
    }

    return ret;
}

extern void
maid_mp_expmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
               const maid_mp_word *mod)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)
        MAID_ALLOC_MP(tmp3, 1)

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;

        maid_mp_mov(words, tmp2, NULL);

        volatile size_t msb = 0;
        volatile bool bit = false;

        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t c = i / maid_mp_bits;
            u8     d = i % maid_mp_bits;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * maid_mp_bits; i++)
        {
            size_t ii = (words * maid_mp_bits) - i - 1;

            size_t c = ii / maid_mp_bits;
            u8     d = ii % maid_mp_bits;
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);

            maid_mp_mov(words, tmp2, a);

            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));
            maid_mp_mulmod(words, a, (i == 0) ? tmp : tmp2, mod);
            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));

            maid_mp_swap(words,  a, tmp3, !bit);
            maid_mp_mulmod(words, a, tmp,  mod);
            maid_mp_swap(words,  a, tmp3, !bit);
        }

        msb = 0;
        bit = false;

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
        MAID_CLEAR_MP(tmp3)
    }
}
