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

extern size_t
maid_mp_words(size_t bits)
{
    size_t ret = bits / maid_mp_bits;

    if ((ret * maid_mp_bits) < bits)
        ret += 1;

    return ret;
}

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
maid_mp_debug(FILE *output, size_t words, const char *name,
              const maid_mp_word *a, bool beautify)
{
    if (output && words && name)
    {
        volatile bool started = false;
        volatile maid_mp_word w = 0;

        fprintf(output, (beautify) ? "%s: \n    " : "%s = 0x", name);
        for (size_t i = 0; i < words; i++)
        {
            w = ((a) ? a[words - 1 - i] : 0x0);
            if (!started && w == 0 && i != words - 1)
                continue;

            if (beautify)
            {
                size_t bytes = sizeof(maid_mp_word);
                for (size_t j = 0; j < bytes; j++)
                {
                    fprintf(output, "%02x", (u8)(w >> ((bytes - 1 - j) * 8)));
                    if (i != words - 1 || j != bytes - 1)
                        fprintf(output, ":");
                    if (i != 0 && i % 2 == 1 &&
                        i != words - 1 && j == bytes - 1)
                        fprintf(output, "\n    ");
                }
            }
            else
                fprintf(output, (started) ? maid_mp_fmt : maid_mp_fmt_ns, w);

            started = true;
        }
        fprintf(output, (beautify) ? "\n\n" : "\n");

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

        /* Uses a lot of space to improve calculations */
        #if defined(__SIZEOF_INT128__)
        unsigned __int128 results[words];
        #else
        MAID_ALLOC_MP(x, 1)
        MAID_ALLOC_MP(y, 1)
        MAID_ALLOC_MP(z, 1)
        MAID_ALLOC_MP(w, 1)

        MAID_ALLOC_MP(xz, 1)
        MAID_ALLOC_MP(xw, 1)
        MAID_ALLOC_MP(yz, 1)
        MAID_ALLOC_MP(yw, 1)

        MAID_ALLOC_MP(org,  1)
        #endif
        MAID_ALLOC_MP(low,  1)
        MAID_ALLOC_MP(high, 1)

        /* Initializes values */
        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);

        #if !defined(__SIZEOF_INT128__)
        const size_t       half = maid_mp_bits / 2;
        const maid_mp_word mask = maid_mp_max >> half;

        /* Splits the values into high and low parts */
        for (size_t i = 0; i < words; i++)
            x[i] = tmp[i] >> half;
        for (size_t i = 0; i < words; i++)
            y[i] = tmp[i] & mask;
        for (size_t i = 0; i < words; i++)
            z[i] = ((b) ? b[i] : (i == 0)) >> half;
        for (size_t i = 0; i < words; i++)
            w[i] = ((b) ? b[i] : (i == 0)) & mask;
        #endif

        for (size_t i = 0; i < words; i++)
        {
            #if defined(__SIZEOF_INT128__)
            for (size_t j = 0; j < words; j++)
                results[j] = tmp[i];
            for (size_t j = 0; j < words; j++)
                results[j] *= ((b) ? b[j] : (j == 0));
            for (size_t j = 0; j < words; j++)
                low[j] = results[j];
            for (size_t j = 0; j < words; j++)
                high[j] = results[j] >> 64;
            #else
            /* Does the intermediary multiplications */
            for (size_t j = 0; j < words; j++)
            {
                xz[j] = x[i] * z[j];
                xw[j] = x[i] * w[j];
                yz[j] = y[i] * z[j];
                yw[j] = y[i] * w[j];
            }

            /* Calculates low part of the words */
            for (size_t j = 0; j < words; j++)
                low[j] = yw[j];

            for (size_t j = 0; j < words; j++)
                org[j] = low[j];
            for (size_t j = 0; j < words; j++)
                low[j] += xw[j] << half;
            for (size_t j = 0; j < words; j++)
                high[j] = (low[j] < org[j]);

            for (size_t j = 0; j < words; j++)
                org[j] = low[j];
            for (size_t j = 0; j < words; j++)
                low[j] += yz[j] << half;
            for (size_t j = 0; j < words; j++)
                high[j] += (low[j] < org[j]);

            /* Calculates high part of the words */
            for (size_t j = 0; j < words; j++)
                high[j] += xz[j];
            for (size_t j = 0; j < words; j++)
                high[j] += xw[j] >> half;
            for (size_t j = 0; j < words; j++)
                high[j] += yz[j] >> half;
            #endif

            /* Adds words to the total */
            maid_mp_mov(words2, tmp2, NULL);
            for (size_t j = 0; j < words && (i + j) < words2; j++)
            {
                size_t idx = (i + j);
                tmp2[idx]     = low[j];
                tmp2[idx + 1] = high[j];

                volatile u8 carry = 0;
                for (size_t k = idx; k < (idx + 3 + j) && k < words2; k++)
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

        #if defined(__SIZEOF_INT128__)
        maid_mem_clear(results, sizeof(results));
        #else
        MAID_CLEAR_MP(x);
        MAID_CLEAR_MP(y);
        MAID_CLEAR_MP(z);
        MAID_CLEAR_MP(w);

        MAID_CLEAR_MP(xz);
        MAID_CLEAR_MP(xw);
        MAID_CLEAR_MP(yz);
        MAID_CLEAR_MP(yw);

        MAID_CLEAR_MP(org);
        #endif
        MAID_CLEAR_MP(low);
        MAID_CLEAR_MP(high);
    }
}

static void
maid_mp_mul_karat_halve(size_t words, maid_mp_word *a, const maid_mp_word *b)
{
    /* Does karatsuba to optimize mulmod,
     * which always have half the higher words empty
     *
     * Depends on words being divisible by four
     * Empirically, starts to be faster around 2048 bits */

    if (words <= 32 || words % 4 != 0)
        maid_mp_mul_long(words, a, b, true);
    else
    {
        /* Trick to allow NULL = 1 */
        volatile maid_mp_word one[words];
        maid_mp_mov(words, (maid_mp_word *)one, NULL);
        one[0] = 1;
        b = (b) ? b : (const maid_mp_word *) one;

        MAID_ALLOC_MP(ac,    1)
        MAID_ALLOC_MP(bd,    1)
        MAID_ALLOC_MP(ab,    1)
        MAID_ALLOC_MP(cd,    1)
        MAID_ALLOC_MP(abcd0, 1)
        MAID_ALLOC_MP(abcd1, 1)
        MAID_ALLOC_MP(abcd2, 1)
        MAID_ALLOC_MP(abcd3, 1)
        MAID_ALLOC_MP(tmp,   1)

        size_t half    = words / 2;
        size_t quarter = words / 4;

        maid_mp_mov(quarter, ac,  &(a[quarter]));
        maid_mp_mov(quarter, tmp, &(b[quarter]));
        maid_mp_mul_karat_halve(half, ac, tmp);

        maid_mp_mov(quarter, bd,  a);
        maid_mp_mov(quarter, tmp, b);
        maid_mp_mul_karat_halve(half, bd, tmp);

        maid_mp_mov(quarter, ab,  &(a[quarter]));
        maid_mp_mov(quarter, tmp, a);
        maid_mp_add(half, ab, tmp);

        maid_mp_mov(quarter, cd,  &(b[quarter]));
        maid_mp_mov(quarter, tmp, b);
        maid_mp_add(half, cd, tmp);

        maid_mp_mov(quarter, abcd0, ab);
        maid_mp_mov(quarter, tmp,   cd);
        maid_mp_mul_karat_halve(half, abcd0, tmp);

        maid_mp_mov(quarter, abcd1, cd[quarter] ? ab : NULL);
        maid_mp_shl(half,    abcd1, maid_mp_bits * quarter);

        maid_mp_mov(quarter, abcd2, ab[quarter] ? cd : NULL);
        maid_mp_shl(half,    abcd2, maid_mp_bits * quarter);

        abcd3[0] = (ab[quarter] && cd[quarter]) ? 1 : 0;
        maid_mp_shl(words, abcd3, maid_mp_bits * half);

        maid_mp_mov(words, tmp, ab);
        maid_mp_mov(words, ab, abcd0);
        maid_mp_add(words, ab, abcd1);
        maid_mp_add(words, ab, abcd2);
        maid_mp_add(words, ab, abcd3);
        maid_mp_sub(words, ab, bd);
        maid_mp_sub(words, ab, ac);

        maid_mp_mov(words, a, bd);
        maid_mp_shl(words, ab, maid_mp_bits * quarter);
        maid_mp_add(words, a, ab);
        maid_mp_shl(words, ac, maid_mp_bits * half);
        maid_mp_add(words, a, ac);

        MAID_CLEAR_MP(ac)
        MAID_CLEAR_MP(bd)
        MAID_CLEAR_MP(ab)
        MAID_CLEAR_MP(cd)
        MAID_CLEAR_MP(abcd0)
        MAID_CLEAR_MP(abcd1)
        MAID_CLEAR_MP(abcd2)
        MAID_CLEAR_MP(abcd3)
        MAID_CLEAR_MP(tmp)

        one[0] = 0;
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
            if (msb && i == 0)
                maid_mp_mul(words, a, tmp);
            else if (msb && ii < (msb - 1))
                maid_mp_mul(words, a, tmp2);
            else
                maid_mp_mul(words, a, NULL);

            if (bit)
                maid_mp_mul(words, a, tmp);
            else
                maid_mp_mul(words, a, NULL);
        }

        msb = 0;
        bit = false;

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
    }
}

extern void
maid_mp_div2(size_t words, maid_mp_word *a, maid_mp_word *rem,
             const maid_mp_word *b)
{
    if (words && a && rem)
    {
        MAID_ALLOC_MP(tmp, 1)

        maid_mp_mov(words, rem, a);
        maid_mp_div(words, a,   b);
        maid_mp_mov(words, tmp, a);

        maid_mp_mul(words, tmp, b);
        maid_mp_sub(words, rem, tmp);

        MAID_CLEAR_MP(tmp)
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

        if (b)
            maid_mp_mul_karat_halve(words * 2, a2, b2);
        else
            maid_mp_mul_karat_halve(words * 2, a2, NULL);

        maid_mp_mod(words * 2, a2, mod2);
        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(mod2)
    }
}

extern void
maid_mp_expmod(size_t words, maid_mp_word *a, const maid_mp_word *b,
               const maid_mp_word *mod, bool constant)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

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
            if (msb && i == 0)
                maid_mp_mulmod(words, a, tmp, mod);
            else if (msb && ii < (msb - 1))
                maid_mp_mulmod(words, a, tmp2, mod);
            else if (constant)
                maid_mp_mulmod(words, a, NULL, mod);

            if (bit)
                maid_mp_mulmod(words, a, tmp, mod);
            else if (constant)
                maid_mp_mulmod(words, a, NULL, mod);
        }

        msb = 0;
        bit = false;

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
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

static void
maid_mp_mont_mulmod(size_t words, maid_mp_word *ma, const maid_mp_word *mb,
                    const maid_mp_word *mod, const maid_mp_word *imod)
{
    if (words && ma && mod)
    {
        MAID_ALLOC_MP(a2,    3)
        MAID_ALLOC_MP(b2,    2)
        MAID_ALLOC_MP(mod2,  2)
        MAID_ALLOC_MP(imod2, 2)
        MAID_ALLOC_MP(acc,   3)

        maid_mp_mov(words, a2,   ma);
        maid_mp_mov(words, b2,   mb);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mov(words + 1, &(a2[words]),   NULL);
        maid_mp_mov(words,     &(b2[words]),   NULL);
        maid_mp_mov(words,     &(mod2[words]), NULL);

        maid_mp_mul_karat_halve(words * 2, a2, (mb) ? b2 : NULL);

        maid_mp_mov(words, &(imod2[words]), NULL);
        maid_mp_mov(words, imod2, imod);

        maid_mp_mov(words * 2, acc, imod2);
        acc[words * 2] = 0x0;

        maid_mp_mul(words * 1, acc, a2);
        maid_mp_mov(words + 1, &(acc[words]), NULL);
        maid_mp_mul_karat_halve(words * 2, acc, mod2);
        maid_mp_add((words * 2) + 1, acc, a2);
        maid_mp_shr((words * 2) + 1, acc, words * maid_mp_bits);

        if (maid_mp_cmp(words * 2, acc, mod2) < 0)
            maid_mp_sub(words * 2, acc, mod2);
        else
            maid_mp_sub(words * 2, acc, NULL);

        maid_mp_mov(words, ma, acc);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(mod2)
        MAID_CLEAR_MP(imod2)
        MAID_CLEAR_MP(acc)
    }
}

static void
maid_mp_mont_in(size_t words, maid_mp_word *a, const maid_mp_word *mod)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(a2,    2)
        MAID_ALLOC_MP(mod2,  2)
        MAID_ALLOC_MP(rmod,  2)

        maid_mp_mov(words * 2, rmod, NULL);
        rmod[words] = 0x1;

        maid_mp_mov(words, &(a2[words]),   NULL);
        maid_mp_mov(words, &(mod2[words]), NULL);
        maid_mp_mov(words, a2,   a);
        maid_mp_mov(words, mod2, mod);

        maid_mp_mulmod(words * 2, a2, rmod, mod2);
        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(mod2)
        MAID_CLEAR_MP(rmod)
    }
}

static void
maid_mp_mont_out(size_t words, maid_mp_word *a, const maid_mp_word *mod,
                 const maid_mp_word *imod)
{
    return maid_mp_mont_mulmod(words, a, NULL, mod, imod);
}

extern void
maid_mp_expmod2(size_t words, maid_mp_word *a, const maid_mp_word *b,
                const maid_mp_word *mod, bool constant)
{
    if (words && a && mod)
    {
        MAID_ALLOC_MP(org,  1)
        MAID_ALLOC_MP(imod, 2)
        MAID_ALLOC_MP(acc,  2)
        MAID_ALLOC_MP(one,  2)

        maid_mp_word *rmod = acc;
        maid_mp_mov(words * 2, rmod, NULL);
        rmod[words] = 0x1;

        maid_mp_mov(words, &(imod[words]), NULL);
        maid_mp_mov(words, imod, mod);
        maid_mp_invmod(words * 2, imod, rmod);

        maid_mp_mov(words * 2, acc, imod);
        maid_mp_mov(words * 2, imod, NULL);
        maid_mp_sub(words * 2, imod, acc);
        maid_mp_mov(words * 2, acc, NULL);

        maid_mp_mont_in(words, a, mod);
        maid_mp_mov(words, org, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;
        maid_mp_mont_in(words, a, mod);
        maid_mp_mov(words, one, a);

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

            maid_mp_mov(words, acc, a);
            if (msb && i == 0)
                maid_mp_mont_mulmod(words, a, org, mod, imod);
            else if (msb && ii < (msb - 1))
                maid_mp_mont_mulmod(words, a, acc, mod, imod);
            else if (constant)
                maid_mp_mont_mulmod(words, a, one, mod, imod);

            if (bit)
                maid_mp_mont_mulmod(words, a, org, mod, imod);
            else if (constant)
                maid_mp_mont_mulmod(words, a, one, mod, imod);
        }

        msb = 0;
        bit = false;

        maid_mp_mont_out(words, a, mod, imod);

        MAID_CLEAR_MP(org)
        MAID_CLEAR_MP(imod)
        MAID_CLEAR_MP(acc)
        MAID_CLEAR_MP(one)
    }
}

extern void
maid_mp_random(size_t words, maid_mp_word *a, maid_rng *g, size_t bits)
{
    if (words && a && g && bits)
    {
        maid_mp_word mask = -1;
        size_t bits2 = maid_mp_bits * words;
        if (bits2 < bits)
            bits = bits2;
        else
            mask >>= bits2 - bits;
        size_t bytes = (bits / 8)            + ((bits %            8) ? 1 : 0);
        size_t last  = (bits / maid_mp_bits) - ((bits % maid_mp_bits) ? 0 : 1);

        maid_mp_mov(words, a, NULL);
        maid_rng_generate(g, (u8*)a, bytes);

        a[last] &= mask;
    }
}

extern void
maid_mp_random2(size_t words, maid_mp_word *a, maid_rng *g,
                const maid_mp_word *low, const maid_mp_word *high)
{
    if (words && a && g)
    {
        MAID_ALLOC_MP(a2, 2)
        MAID_ALLOC_MP(b2, 2)

        maid_mp_random(words, a, g, words * maid_mp_bits);

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b2, high);
        maid_mp_sub(words, b2, low);
        maid_mp_mul(words * 2, a2, b2);

        /* Same as division by 0x10000... */
        maid_mp_mov(words, a, &(a2[words]));
        maid_mp_add(words, a, low);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
    }
}

static bool
maid_mp_fastgcd1(size_t words, const maid_mp_word *a, const maid_mp_word *b)
{
    /* Returns GCD(a, b) == 1 in non-constant time */

    bool ret = false;

    if (words && a && b)
    {
        MAID_ALLOC_MP(a2,   1)
        MAID_ALLOC_MP(b2,   1)
        MAID_ALLOC_MP(zero, 1)
        MAID_ALLOC_MP(or,   1)

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b2, b);
        maid_mp_mov(words, zero, NULL);

        if (maid_mp_cmp(words, a, zero) != 0 &&
            maid_mp_cmp(words, b, zero) != 0)
        {
            volatile size_t k = 0;

            while (true)
            {
                maid_mp_mov(words, or, a2);
                maid_mp_orr(words, or, b2);
                if (!(or[0] & 0x1))
                {
                    maid_mp_shr(words, a2, 1);
                    maid_mp_shr(words, b2, 1);
                    k++;
                }
                else
                    break;
            }

            while (!(a2[0] & 0x1))
                maid_mp_shr(words, a2, 1);

            while (maid_mp_cmp(words, b2, zero) != 0)
            {
                while (!(b2[0] & 0x1))
                    maid_mp_shr(words, b2, 1);

                if (maid_mp_cmp(words, a2, b2) < 0)
                {
                    maid_mp_mov(words, or, a2);
                    maid_mp_mov(words, a2, b2);
                    maid_mp_mov(words, b2, or);
                }

                maid_mp_sub(words, b2, a2);
            }

            zero[0] = 1;
            if (k == 0 && maid_mp_cmp(words, a2, zero) == 0)
                ret = true;

            k = 0;
        }

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
        MAID_CLEAR_MP(zero)
        MAID_CLEAR_MP(or)
    }

    return ret;
}


static bool
maid_mp_sprp(size_t words, const maid_mp_word *a, maid_rng *g, size_t rounds)
{
    bool ret = false;

    /* Not constant time, as it's very slow and unnecessary here */
    if (words && a && g && rounds)
    {
        volatile bool finished = false;

        /* Tests if odd or even */
        ret = a[0] & 0x1;
        if (!ret)
            finished = true;

        /* Checks if it's 1 (non-prime) or 2 (prime) */
        MAID_ALLOC_MP(check, 1)
        check[0] = (ret) ? 0x01 : 0x02;
        if (maid_mp_cmp(words, a, check) == 0)
        {
            ret = !ret;
            finished = true;
        }
        MAID_CLEAR_MP(check)

        /* Does a trial division test with small primes */
        if (!finished)
        {
            /* Product of primes from 3 to 751 (from SP800-89) */
            const u8 sp[] =
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                 0x13, 0x8e, 0x8a, 0x0f, 0xcf, 0x3a, 0x4e, 0x84,
                 0xa7, 0x71, 0xd4, 0x0f, 0xd3, 0x05, 0xd7, 0xf4,
                 0xaa, 0x59, 0x30, 0x6d, 0x72, 0x51, 0xde, 0x54,
                 0xd9, 0x8a, 0xf8, 0xfe, 0x95, 0x72, 0x9a, 0x1f,
                 0x73, 0xd8, 0x93, 0xfa, 0x42, 0x4c, 0xd2, 0xed,
                 0xc8, 0x63, 0x6a, 0x6c, 0x32, 0x85, 0xe0, 0x22,
                 0xb0, 0xe3, 0x86, 0x6a, 0x56, 0x5a, 0xe8, 0x10,
                 0x8e, 0xed, 0x85, 0x91, 0xcd, 0x4f, 0xe8, 0xd2,
                 0xce, 0x86, 0x16, 0x5a, 0x97, 0x8d, 0x71, 0x9e,
                 0xbf, 0x64, 0x7f, 0x36, 0x2d, 0x33, 0xfc, 0xa2,
                 0x9c, 0xd1, 0x79, 0xfb, 0x42, 0x40, 0x1c, 0xba,
                 0xf3, 0xdf, 0x0c, 0x61, 0x40, 0x56, 0xf9, 0xc8,
                 0xf3, 0xcf, 0xd5, 0x1e, 0x47, 0x4a, 0xfb, 0x6b,
                 0xc6, 0x97, 0x4f, 0x78, 0xdb, 0x8a, 0xba, 0x8e,
                 0x9e, 0x51, 0x7f, 0xde, 0xd6, 0x58, 0x59, 0x1a,
                 0xb7, 0x50, 0x2b, 0xd4, 0x18, 0x49, 0x46, 0x2f};

            MAID_ALLOC_MP(p, 1)
            maid_mp_mov(words, p, NULL);
            p[0] = 741;

            if (maid_mp_cmp(words, a, p) < 0)
            {
                u8 sp_words = maid_mp_words(sizeof(sp) * 8);
                if (words > sp_words)
                    sp_words = words;

                size_t org = words;
                words = sp_words;
                MAID_ALLOC_MP(p2, 1)
                MAID_ALLOC_MP(a2, 1)
                MAID_ALLOC_MP(one, 1)

                maid_mp_read(words, p2, sp, true);
                maid_mp_mov(words, a2, NULL);
                maid_mp_mov(org, a2, a);
                maid_mp_mov(words, one, NULL);
                one[0] = 1;

                if (!maid_mp_fastgcd1(org, a2, p2))
                {
                    ret = false;
                    finished = true;
                }

                MAID_CLEAR_MP(p2)
                MAID_CLEAR_MP(a2)
                MAID_CLEAR_MP(one)
                words = org;
            }

            MAID_CLEAR_MP(p)
        }

        /* Does a probabilistic Miller-Rabin test */
        if (!finished)
        {
            MAID_ALLOC_MP(m,    1)
            MAID_ALLOC_MP(one,  1)
            MAID_ALLOC_MP(low,  1)
            MAID_ALLOC_MP(high, 1)
            MAID_ALLOC_MP(b,    1)
            MAID_ALLOC_MP(b2  , 1)

            maid_mp_mov(words, m, a);
            maid_mp_mov(words, one, NULL);
            one[0] = 0x1;
            maid_mp_sub(words, m, one);

            maid_mp_mov(words, low, NULL);
            low[0] = 0x2;
            maid_mp_mov(words, high, m);

            volatile size_t r = 0, c = 0;
            for (size_t i = 0; i < words; i++)
            {
                r  = m[i] & -m[i];
                c  = i;

                if (a[i] != 0)
                    break;
            }

            volatile size_t k = 0;
            for (size_t i = 0; i < maid_mp_bits; i++)
            {
                if (r <= 1)
                    break;

                r >>= 1;
                k++;
            }
            k += c * maid_mp_bits;
            r = 0, c = 0;
            maid_mp_shr(words, m, k);

            for (size_t i = 0; ret && i < rounds; i++)
            {
                maid_mp_random2(words, b, g, low, high);
                maid_mp_expmod2(words, b, m, a, false);

                if (maid_mp_cmp(words, b, one)  == 0 ||
                    maid_mp_cmp(words, b, high) == 0)
                    continue;

                for (size_t j = 0; j < (k - 1); j++)
                {
                    maid_mp_mov(words, b2, b);
                    maid_mp_mulmod(words, b, b2, a);

                    if (maid_mp_cmp(words, b, high) == 0)
                    {
                        finished = true;
                        break;
                    }
                }

                if (!finished)
                {
                    ret = false;
                    break;
                }
                finished = false;
            }
            k = 0;

            MAID_CLEAR_MP(m)
            MAID_CLEAR_MP(one)
            MAID_CLEAR_MP(low)
            MAID_CLEAR_MP(high)
            MAID_CLEAR_MP(b)
            MAID_CLEAR_MP(b2)
        }

        finished = false;
    }

    return ret;
}

extern void
maid_mp_prime(size_t words, maid_mp_word *a, maid_rng *g,
              size_t bits, size_t safety)
{
    if (words && a && g && bits && safety)
    {
        maid_mp_mov(words, a, NULL);

        size_t words2 = maid_mp_words(bits);
        if (words2 < words)
            words = words2;

        do
        {
            maid_mp_random(words, a, g, bits);
            a[0] |= 1;
        }
        while (!maid_mp_sprp(words, a, g, (safety > 1) ? safety / 2 : 1));
    }
}
