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
#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>
#include <maid/mp.h>

#include <maid/ff.h>

struct maid_ff
{
    size_t words;

    size_t k;
    maid_mp_word *c;
    size_t cs;
    bool minus;

    size_t folds, subs;

    maid_mp_word *full;
};

extern struct maid_ff *
maid_ff_new(enum maid_ff_prime prime)
{
    struct maid_ff *ret = calloc(1, sizeof(struct maid_ff));

    if (ret)
    {
        switch (prime)
        {
            case MAID_FF_1305:
            case MAID_FF_25519:
                ret->words = MAID_MP_WORDS(256) * 2;
                ret->cs    = 1;

                ret->c    = calloc(ret->words, sizeof(maid_mp_word));
                ret->full = calloc(ret->words, sizeof(maid_mp_word));
                if (ret->c && ret->full)
                {
                    switch (prime)
                    {
                        case MAID_FF_1305:
                            ret->k     = 130;
                            ret->c[0]  = 5;
                            break;
                        case MAID_FF_25519:
                            ret->k     = 255;
                            ret->c[0]  = 19;
                            break;
                        default:
                            break;
                    }
                    ret->minus = true;

                    ret->folds = 2;
                    ret->subs  = 1;
                }
                else
                    ret = maid_ff_del(ret);
                break;

            case MAID_FF_ORDER25519:
                ret->words = MAID_MP_WORDS(512) * 2;
                ret->cs    = ret->words;

                ret->c    = calloc(ret->words, sizeof(maid_mp_word));
                ret->full = calloc(ret->words, sizeof(maid_mp_word));
                if (ret->c && ret->full)
                {
                    uint8_t c[] = {0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c,
                                   0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5,
                                   0xd3, 0xed};
                    ret->k = 252;
                    maid_mp_read(MAID_MP_WORDS(128), ret->c, c, true);
                    ret->minus = false;

                    ret->folds = 4;
                    ret->subs  = 1;
                }
                else
                    ret = maid_ff_del(ret);
                break;

            default:
                break;
        }
    }

    if (ret)
    {
        while (ret->cs)
        {
            if (ret->c[ret->cs - 1] == 0)
                ret->cs--;
            else
                break;
        }

        ret->full[ret->k / MAID_MP_BITS(1)] =
            1ULL << (ret->k % MAID_MP_BITS(1));
        if (ret->minus)
            maid_mp_sub(ret->words, ret->full, ret->c);
        else
            maid_mp_add(ret->words, ret->full, ret->c);
    }

    return ret;
}

extern maid_ff *
maid_ff_del(struct maid_ff *ff)
{
    if (ff)
    {
        maid_mp_mov(ff->words, ff->c,    NULL);
        maid_mp_mov(ff->words, ff->full, NULL);
        free(ff->c);
        free(ff->full);

        maid_mem_clear(ff, sizeof(struct maid_ff));
    }
    free(ff);

    return NULL;
}

extern maid_mp_word *
maid_ff_prime(const struct maid_ff *ff)
{
    maid_mp_word *ret = NULL;

    if (ff)
        ret = ff->full;

    return ret;
}

extern void
maid_ff_mod(size_t words, maid_mp_word *a, const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        size_t words2 = words + ff->cs + 1;
        maid_mp_word tmp [words2];
        maid_mp_word tmp2[words2];
        maid_mp_word tmp3[words2];
        for (u8 i = 0; i < ff->folds; i++)
        {
            maid_mem_clear(tmp,  sizeof(tmp));
            maid_mem_clear(tmp2, sizeof(tmp2));
            maid_mem_clear(tmp3, sizeof(tmp3));

            /* Low part mask */
            tmp[ff->k / MAID_MP_BITS(1)] |= 1ULL << (ff->k % MAID_MP_BITS(1));
            tmp2[0] = 1;
            maid_mp_sub(words, tmp, tmp2);

            /* High part mask */
            maid_mp_mov(words, tmp2, tmp);
            maid_mp_not(words, tmp2);

            /* Masking */
            maid_mp_and(words, tmp,  a);
            maid_mp_and(words, tmp2, a);
            maid_mp_shr(words, tmp2, ff->k);

            /* Folding */
            maid_mp_mul(words, tmp2, ff->c);
            if (ff->minus)
                maid_mp_add(words, tmp2, tmp);
            else
            {
                maid_mp_mov(words, tmp3, ff->full);
                maid_mp_sub(words, tmp3, tmp);
                maid_mp_add(words, tmp2, tmp3);
            }
            maid_mp_mov(words, a, tmp2);
        }

        /* Correction */
        maid_mp_mov(words2, tmp, NULL);
        maid_mp_mov(words, tmp, ff->full);

        volatile bool sub = false;
        for (u8 i = 0; i < ff->subs; i++)
        {
            sub = maid_mp_cmp(words2, tmp2, tmp) < 0;
            maid_mp_swap(words2, tmp2, tmp3, !sub);
            maid_mp_sub(words2, tmp2, tmp);
            maid_mp_swap(words2, tmp2, tmp3, !sub);
        }
        sub = false;

        /* Result */
        maid_mp_mov(words, a, tmp2);

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
        MAID_CLEAR_MP(tmp3)
    }
}

extern void
maid_ff_add(size_t words, maid_mp_word *a, const maid_mp_word *b,
            const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        MAID_ALLOC_MP(a2, 2)
        MAID_ALLOC_MP(b2, 2)

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b2, b);

        maid_mp_add(words + 1, a2, b2);

        maid_ff_mod(words + 1, a2, ff);
        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
    }
}

extern void
maid_ff_sub(size_t words, maid_mp_word *a, const maid_mp_word *b,
            const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        MAID_ALLOC_MP(buf,  1)
        MAID_ALLOC_MP(buf2, 1)

        maid_mp_mov(words, buf, b);
        maid_ff_mod(words, buf, ff);
        maid_mp_mov(words, buf2, ff->full);
        maid_mp_sub(words, buf2, buf);

        maid_ff_add(words, a, buf2, ff);

        MAID_CLEAR_MP(buf)
        MAID_CLEAR_MP(buf2)
    }
}

static void
mul_fast(size_t words, maid_mp_word *a, const maid_mp_word *b,
         const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

        /* Halving optimizes mul, no need to consider odd word length */
        size_t words2 = words;
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
            maid_mp_mov(words2, tmp2, NULL);
            for (size_t j = 0; j < words && (i + j) < words2; j++)
            {
                size_t idx = (i + j);
                tmp2[idx]     = low[j];
                tmp2[idx + 1] = high[j];
                maid_mp_add(words2 - idx, &(a[idx]), &(tmp2[idx]));
            }
        }

        MAID_CLEAR_MP(tmp);
        MAID_CLEAR_MP(tmp2);

        MAID_CLEAR_MP(low);
        MAID_CLEAR_MP(high);
    }
}

extern void
maid_ff_mul(size_t words, maid_mp_word *a, const maid_mp_word *b,
            const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        MAID_ALLOC_MP(a2, 2)
        MAID_ALLOC_MP(b2, 2)

        maid_mp_mov(words, a2, a);
        maid_mp_mov(words, b2, b);
        maid_ff_mod(words, a2, ff);
        maid_ff_mod(words, b2, ff);

        mul_fast(words * 2, a2, b2, ff);
        maid_ff_mod(words * 2, a2, ff);

        maid_mp_mov(words, a, a2);

        MAID_CLEAR_MP(a2)
        MAID_CLEAR_MP(b2)
    }
}

static void
exp_fast(size_t words, maid_mp_word *a, const maid_mp_word *b,
         const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

        maid_mp_mov(words, tmp, a);
        maid_mp_mov(words, a, NULL);
        a[0] = 0x1;

        maid_mp_mov(words, tmp2, NULL);

        size_t msb = 0;
        bool start = false;
        for (size_t i = 0; i < words * MAID_MP_BITS(1); i++)
        {
            size_t ii = (words * MAID_MP_BITS(1)) - i - 1;

            size_t c = ii / MAID_MP_BITS(1);
            u8     d = ii % MAID_MP_BITS(1);
            bool bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);

            if (!start)
            {
                if (bit)
                {
                    msb = ii;
                    start = true;
                }
                else
                    continue;
            }

            maid_mp_mov(words, tmp2, a);
            if (msb && ii <= (msb - 1))
                maid_ff_mul(words, a, (i == 0) ? tmp : tmp2, ff);
            if (bit)
                maid_ff_mul(words, a, tmp, ff);
        }

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
    }
}

extern bool
maid_ff_inv(size_t words, maid_mp_word *a, const struct maid_ff *ff)
{
    bool ret = false;

    if (words && a && ff && words <= ff->words &&
        maid_mp_cmp(words, a, NULL) != 0)
    {
        MAID_ALLOC_MP(tmp,  1)
        MAID_ALLOC_MP(tmp2, 1)

        maid_mp_mov(words, tmp, ff->full);
        tmp2[0] = 2;
        maid_mp_sub(words, tmp, tmp2);
        exp_fast(words, a, tmp, ff);

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)

        ret = true;
    }

    return ret;
}

extern void
maid_ff_exp(size_t words, maid_mp_word *a, const maid_mp_word *b,
            const struct maid_ff *ff)
{
    if (words && a && ff && words <= ff->words)
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

        for (size_t i = 0; i < words * MAID_MP_BITS(1); i++)
        {
            size_t c = i / MAID_MP_BITS(1);
            u8     d = i % MAID_MP_BITS(1);
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);
            msb = (bit) ? i : msb;
        }

        for (size_t i = 0; i < words * MAID_MP_BITS(1); i++)
        {
            size_t ii = (words * MAID_MP_BITS(1)) - i - 1;

            size_t c = ii / MAID_MP_BITS(1);
            u8     d = ii % MAID_MP_BITS(1);
            bit = ((b) ? b[c] : ((c == 0) ? 0x1 : 0x0)) & (1ULL << d);

            maid_mp_mov(words, tmp2, a);

            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));
            maid_ff_mul(words, a, (i == 0) ? tmp : tmp2, ff);
            maid_mp_swap(words, a, tmp3, !(msb && ii <= (msb - 1)));

            maid_mp_swap(words,  a, tmp3, !bit);
            maid_ff_mul(words, a, tmp, ff);
            maid_mp_swap(words,  a, tmp3, !bit);
        }

        msb = 0;
        bit = false;

        MAID_CLEAR_MP(tmp)
        MAID_CLEAR_MP(tmp2)
        MAID_CLEAR_MP(tmp3)
    }
}
