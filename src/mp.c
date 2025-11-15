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

#include <maid/mp.h>
#include <maid/mem.h>

#include <internal/mp.h>
#include <internal/types.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

extern void
maid_mp_read(size_t words, maid_mp_word *a, const u8 *addr, bool big)
{
    if (words && a && addr)
    {
        for (size_t i = 0; i < words; i++)
        {
            maid_mp_word val = maid_mem_read(addr, (!big) ? i : words - i - 1,
                                             MAID_MP_BYTES(1), big);
            maid_mem_write(a, i, MAID_MP_BYTES(1), false, val);
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
                           MAID_MP_BYTES(1), big, (a) ? a[i] : 0x0);
        }
    }
}

extern void
maid_mp_debug(size_t words, const char *name, const maid_mp_word *a)
{
    if (words && name)
    {
        const char *maid_mp_fmt    = "%016lx";
        const char *maid_mp_fmt_ns = "%lx";

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
            a[i] &= (b) ? b[i] : MAID_MP_MAX;
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
        MAID_MP_ALLOC(mask, 1)
        MAID_MP_ALLOC(tmp,  1)

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

        MAID_MP_CLEAR(mask)
        MAID_MP_CLEAR(tmp)
    }
}

extern void
maid_mp_shl(size_t words, maid_mp_word *a, size_t shift)
{
    if (words && a)
    {
        const       size_t c = shift / MAID_MP_BITS(1);
        const          u8  d = shift % MAID_MP_BITS(1);
        const          u8 id = (MAID_MP_BITS(1) - d) % MAID_MP_BITS(1);
        const maid_mp_word m = d ? (1ULL << id) - 1 : MAID_MP_MAX;

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
        const       size_t c = shift / MAID_MP_BITS(1);
        const          u8  d = shift % MAID_MP_BITS(1);
        const          u8 id = (MAID_MP_BITS(1) - d) % MAID_MP_BITS(1);
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
                                      (1ULL << (MAID_MP_BITS(1) - 1))) ?
                                     MAID_MP_MAX: 0x00;

        const       size_t c = shift / MAID_MP_BITS(1);
        const          u8  d = shift % MAID_MP_BITS(1);
        const          u8 id = (MAID_MP_BITS(1) - d) % MAID_MP_BITS(1);
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
maid_mp_mul(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    if (words && a)
    {
        MAID_MP_ALLOC(tmp,  1)
        MAID_MP_ALLOC(tmp2, 1)

        /* Uses a bit of space to improve calculations */
        MAID_MP_ALLOC(low,  1)
        MAID_MP_ALLOC(high, 1)

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
            const size_t       half = MAID_MP_BITS(1) / 2;
            const maid_mp_word mask = MAID_MP_MAX >> half;

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
            maid_mp_mov(words, tmp2, NULL);
            for (size_t j = 0; j < words && (i + j) < words; j++)
            {
                size_t idx = (i + j);
                tmp2[idx]     = low[j];
                tmp2[idx + 1] = high[j];
                maid_mp_add(words - idx, &(a[idx]), &(tmp2[idx]));
            }
        }

        MAID_MP_CLEAR(tmp);
        MAID_MP_CLEAR(tmp2);

        MAID_MP_CLEAR(low);
        MAID_MP_CLEAR(high);
    }
}
