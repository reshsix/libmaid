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

#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>
#include <maid/mp.h>

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>
#include <maid/rng.h>
#include <maid/hash.h>

#include <maid/rsa.h>
#include <maid/ecc.h>
#include <maid/pem.h>
#include <maid/asn1.h>
#include <maid/spki.h>
#include <maid/pkcs8.h>
#include <maid/sign.h>
#include <maid/kex.h>

/* Test macros */

#define TEST_EMPTY(name, dlen) \
    u8 name[strlen(dlen) / 2]; \
    maid_mem_clear(name, sizeof(name));

#define TEST_IMPORT(name, input) \
    u8 name[strlen(input) / 2]; \
    ret &= (maid_mem_import(MAID_BASE16L, name,  sizeof(name), \
                            input, strlen(input)) == strlen(input));

#define TEST_EMPTY_MP(words, name) \
    maid_mp_word name[words]; \
    if (ret) \
        maid_mp_mov(words, name, NULL);

#define TEST_IMPORT_MP(words, name, buf, input) \
    u8 buf[strlen(input) / 2]; \
    if (ret) \
        ret &= (maid_mem_import(MAID_BASE16L, buf,  sizeof(buf), \
                                input, strlen(input)) == strlen(input)); \
    maid_mp_word name[words]; \
    if (ret) \
        maid_mp_read(words, name, buf, true);

#define TEST_REIMPORT_MP(words, name, buf) \
    if (ret) \
        maid_mp_read(words, name, buf, true); \

/* Test functions */

static bool
test_mem_import(enum maid_mem t, char *input, char *output)
{
    size_t l  = strlen(input);
    size_t l2 = strlen(output);

    char buf[l2 + 1];
    maid_mem_clear(buf, sizeof(buf));

    return maid_mem_import(t, buf, sizeof(buf), input, l) == l &&
           memcmp(buf, output, l2) == 0 && buf[l2] == '\0';
}

static bool
test_mem_export(enum maid_mem t, char *input, char *output)
{
    size_t l  = strlen(input);
    size_t l2 = strlen(output);

    char buf[l2 + 1];
    maid_mem_clear(buf, sizeof(buf));

    return maid_mem_export(t, input, l, buf, sizeof(buf)) == l2 &&
           memcmp(buf, output, l2) == 0 && buf[l2] == '\0';
}

static bool
test_mp_rw(size_t words, char *a, char *r)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        maid_mp_write(words, am, ab, false);
        maid_mp_read(words, am, ab, true);
        ret &= maid_mem_cmp(am, rm, size);
    }

    return ret;
}

static bool
test_mp_not(size_t words, char *a)
{
    bool ret = true;

    TEST_EMPTY_MP(words, zm)
    TEST_IMPORT_MP(words, am, ab, a)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        for (size_t i = 0; i < words; i++)
            zm[i] = ~(am[i]);

        maid_mp_not(words, am);
        ret &= maid_mem_cmp(am, zm, size);
    }

    return ret;
}

static bool
test_mp_a(size_t words,
          void (*f)(size_t, maid_mp_word *, const maid_mp_word *),
          char *a, char *b, bool zeros, char *r)
{
    bool ret = true;

    TEST_EMPTY_MP(words, zm)
    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, bm, bb, b)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        f(words, am, bm);
        ret &= maid_mem_cmp(am, rm, size);
    }

    if (ret)
    {
        f(words, am, NULL);
        ret &= maid_mem_cmp(am, (zeros) ? zm : rm, size);
    }

    return ret;
}

static bool
test_mp_cmp(size_t words, char *bigger, char *smaller)
{
    bool ret = true;

    TEST_IMPORT_MP(words, bm, bb, bigger)
    TEST_IMPORT_MP(words, sm, sb, smaller)

    ret &= maid_mp_cmp(words, bm, sm)    == -1 &&
           maid_mp_cmp(words, sm, bm)    ==  1 &&
           maid_mp_cmp(words, bm, bm)    ==  0 &&
           maid_mp_cmp(words, sm, sm)    ==  0 &&
           maid_mp_cmp(words, bm, NULL)  == -1 &&
           maid_mp_cmp(words, NULL, sm)  ==  1;

    return ret;
}

static bool
test_mp_s(size_t words, void (*f)(size_t, maid_mp_word *, size_t),
          char *a, size_t shift, bool zeros, char *r)
{
    bool ret = true;

    TEST_EMPTY_MP(words, zm)
    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        f(words, am, shift);
        ret &= maid_mem_cmp(am, rm, size);
    }

    if (ret)
    {
        f(words, am, size * 8);
        if (!zeros)
        {
            TEST_EMPTY_MP(words, one)
            one[0] = 1;

            maid_mp_sub(words, zm, one);
        }
        ret &= maid_mem_cmp(am, zm, size);
    }

    return ret;
}

static bool
test_mp_div2(size_t words, char *a, char *b, char *r, char *m)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, bm, bb, b)
    TEST_IMPORT_MP(words, rm, rb, r)
    TEST_IMPORT_MP(words, mm, mb, m)
    TEST_EMPTY_MP(words, mm2)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        maid_mp_div2(words, am, mm2, bm);
        ret &= maid_mem_cmp(am, rm,  size) &&
               maid_mem_cmp(mm, mm2, size);
    }

    if (ret)
    {
        TEST_REIMPORT_MP(words, am, ab);
        maid_mp_mov(words, rm,  am);
        maid_mp_mov(words, mm2, bm);
        maid_mp_div2(words, am, mm2, NULL);
        ret &= maid_mem_cmp(am, rm,  size);
               maid_mem_cmp(bm, mm2, size);
    }

    return ret;
}

static bool
test_mp_mulmod(size_t words, char *a, char *b, char *m, char *r)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, bm, bb, b)
    TEST_IMPORT_MP(words, mm, mb, m)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        maid_mp_mulmod(words, am, bm, mm);
        ret &= maid_mem_cmp(am, rm, size);
    }

    return ret;
}

static bool
test_mp_expmod(size_t words,
               void (*f)(size_t, maid_mp_word *, const maid_mp_word *,
                         const maid_mp_word *, bool),
               char *a, char *b, char *m, char *r)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, bm, bb, b)
    TEST_IMPORT_MP(words, mm, mb, m)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        f(words, am, bm, mm, false);
        ret &= maid_mem_cmp(am, rm, size);
    }

    if (ret)
    {
        TEST_REIMPORT_MP(words, am, ab);
        f(words, am, bm, mm, true);
        ret &= maid_mem_cmp(am, rm, size);
    }

    return ret;
}

static bool
test_mp_invmod(size_t words, char *a, char *n, char *m, char *r)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, nm, nb, n)
    TEST_IMPORT_MP(words, mm, mb, m)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
        ret &= !maid_mp_invmod(words, nm, mm);

    if (ret)
        ret &= maid_mp_invmod(words, am, mm);

    if (ret)
        ret &= maid_mem_cmp(am, rm, size);

    return ret;
}

static bool
test_mp_random(size_t words, maid_rng *g, u8 exp, u8 exp2)
{
    bool ret = true;

    size_t bits = sizeof(maid_mp_word) * 8;

    /* Limit = middle / 2^exp */
    size_t middle = (words * bits) / 2;
    size_t limit = middle >> exp;
    size_t low  = middle - limit;
    size_t high = middle + limit;

    TEST_EMPTY_MP(words, rm)
    for (size_t i = 0; i < (1ULL << exp2); i++)
    {
        maid_mp_random(words, rm, g, words * bits);

        size_t iset = 0;
        for (size_t i = 0; i < words; i++)
            for (u8 j = 0; j < bits; j++)
                if (rm[i] & (1ULL << j))
                    iset++;

        if (iset <= low || iset >= high)
        {
            ret = false;
            break;
        }
    }

    return ret;
}

static bool
test_mp_random2(size_t words, maid_rng *g,
                char *low, char *high, u8 exp, u8 exp2)
{
    bool ret = true;

    TEST_IMPORT_MP(words, lm, lb, low)
    TEST_IMPORT_MP(words, hm, hb, high)
    TEST_EMPTY_MP(words, rm)
    TEST_EMPTY_MP(words, am)

    for (size_t i = 0; i < (1ULL << exp2); i++)
    {
        maid_mp_random2(words, rm, g, lm, hm);

        if (maid_mp_cmp(words, rm, lm) > 0 ||
            maid_mp_cmp(words, rm, hm) < 0)
        {
            ret = false;
            break;
        }

        /* Average of the results */
        maid_mp_shr(words, rm, exp2);
        maid_mp_add(words, am, rm);
    }

    if (ret)
    {
        /* Middle value */
        TEST_EMPTY_MP(words, mm)
        maid_mp_shr(words, lm, 1);
        maid_mp_shr(words, hm, 1);
        maid_mp_add(words, mm, hm);
        maid_mp_add(words, mm, lm);

        /* Limit value */
        TEST_EMPTY_MP(words, im)
        maid_mp_mov(words, im, mm);
        maid_mp_shr(words, im, exp);

        /* New lowest */
        maid_mp_mov(words, lm, mm);
        maid_mp_sub(words, lm, im);

        /* New highest */
        maid_mp_mov(words, hm, mm);
        maid_mp_add(words, hm, im);

        /* Checks if the average is smaller than the lowest,
         * or higher than the highest (unless it overflows) */
        if (maid_mp_cmp(words, am, lm) > 0 ||
            (maid_mp_cmp(words, am, hm) < 0 &&
             maid_mp_cmp(words, hm, im) < 0))
            ret = false;
    }

    return ret;
}

static bool
test_mp_prime(size_t words, maid_rng *g)
{
    bool ret = true;

    TEST_EMPTY_MP(words, am)
    TEST_EMPTY_MP(words, bm)

    size_t bits = (sizeof(maid_mp_word) * words * 8) / 2;
    maid_mp_prime(words, am, g, bits, 16);
    maid_mp_prime(words, bm, g, bits, 16);

    TEST_EMPTY_MP(words, cm)
    /* c = ab */
    maid_mp_mov(words, cm, am);
    maid_mp_mul(words, cm, bm);

    TEST_EMPTY_MP(words, dm)
    TEST_EMPTY_MP(words, om)
    /* b = tot(ab) */
    maid_mp_mov(words, dm, am);
    om[0] = 1;
    maid_mp_sub(words, bm, om);
    maid_mp_sub(words, dm, om);
    maid_mp_mul(words, bm, dm);

    /* 2^tot(ab) % ab = 1 */
    om[0] = 2;
    maid_mp_expmod(words, om, bm, cm, false);
    maid_mp_mov(words, cm, NULL);
    cm[0] = 1;
    if (maid_mp_cmp(words, om, cm) != 0)
        ret = false;

    return ret;
}

static bool
test_ecb(struct maid_block_def def, char *key,
         char *input, char *output, bool decrypt)
{
    bool ret = true;

    TEST_EMPTY(empty,  key);
    TEST_EMPTY(empty2, key);

    maid_block *bl = maid_block_new(def, empty, empty);
    if (bl)
    {
        TEST_IMPORT(key_b,    key);
        TEST_IMPORT(input_b,  input);
        TEST_IMPORT(output_b, output);

        if (ret)
        {
            maid_block_renew(bl, key_b, NULL);
            maid_block_ecb(bl, input_b, decrypt);
            ret = maid_mem_cmp(input_b, output_b, sizeof(output_b));
        }
    }
    else
        ret = false;
    maid_block_del(bl);

    return ret;
}

static bool
test_ctr(struct maid_block_def def, char *key, char *iv,
         char *input, char *output)
{
    bool ret = true;

    TEST_EMPTY(empty,  key);
    TEST_EMPTY(empty2, iv);

    maid_block *bl = maid_block_new(def, empty, empty2);
    if (bl)
    {
        TEST_IMPORT(key_b,    key);
        TEST_IMPORT(iv_b,     iv);
        TEST_IMPORT(input_b,  input);
        TEST_IMPORT(output_b, output);

        if (ret)
        {
            maid_block_renew(bl, key_b, iv_b);
            maid_block_ctr(bl, input_b, sizeof(output_b));
            ret = maid_mem_cmp(input_b, output_b, sizeof(output_b));
        }
    }
    else
        ret = false;
    maid_block_del(bl);

    return ret;
}

static bool
test_stream(struct maid_stream_def def, char *key, char *nonce, u32 counter,
            char *input, char *output)
{
    bool ret = true;

    TEST_EMPTY(empty,  key);
    TEST_EMPTY(empty2, nonce);

    maid_stream *st = maid_stream_new(def, empty, empty2, 0);
    if (st)
    {
        TEST_IMPORT(key_b,    key);
        TEST_IMPORT(nonce_b,  nonce);
        TEST_IMPORT(input_b,  input);
        TEST_IMPORT(output_b, output);

        if (ret)
        {
            maid_stream_renew(st, key_b, nonce_b, counter);
            maid_stream_xor(st, input_b, sizeof(output_b));
            ret = maid_mem_cmp(input_b, output_b, sizeof(output_b));
        }
    }
    else
        ret = false;
    maid_stream_del(st);

    return ret;
}

static bool
test_mac(struct maid_mac_def def, char *key, char *input, char *tag)
{
    bool ret = true;

    TEST_EMPTY(empty, key);

    maid_mac *m = maid_mac_new(def, empty);
    if (m)
    {
        TEST_IMPORT(key_b,   key);
        TEST_IMPORT(input_b, input);
        TEST_IMPORT(tag_b,   tag);

        if (ret)
        {
            maid_mac_renew(m, key_b);
            maid_mac_update(m, input_b, sizeof(input_b));

            TEST_EMPTY(tag2_b, tag);
            maid_mac_digest(m, tag2_b);
            ret = maid_mem_cmp(tag_b, tag2_b, sizeof(tag_b));
        }
    }
    else
        ret = false;
    maid_mac_del(m);

    return ret;
}

static bool
test_aead(struct maid_aead_def def, char *key, char *nonce,
          char *ad, char *input, char *output, char *tag, bool decrypt)
{
    bool ret = true;

    TEST_EMPTY(empty,  key)
    TEST_EMPTY(empty2, nonce)

    maid_aead *ae = maid_aead_new(def, empty, empty2);
    if (ae)
    {
        TEST_IMPORT(key_b,    key)
        TEST_IMPORT(nonce_b,  nonce)
        TEST_IMPORT(ad_b,     ad)
        TEST_IMPORT(input_b,  input)
        TEST_IMPORT(output_b, output)
        TEST_IMPORT(tag_b,    tag)

        if (ret)
        {
            maid_aead_renew(ae, key_b, nonce_b);
            maid_aead_update(ae, ad_b, sizeof(ad_b));
            maid_aead_crypt(ae, input_b, sizeof(input_b), decrypt);

            TEST_EMPTY(tag2_b, tag)
            maid_aead_digest(ae, tag2_b);

            ret = maid_mem_cmp(input_b, output_b, sizeof(input_b)) &&
                  maid_mem_cmp(tag2_b,  tag_b,    sizeof(tag));
        }
    }
    else
        ret = false;
    maid_aead_del(ae);

    return ret;
}

static bool
test_hash(struct maid_hash_def def, char *input, char *output)
{
    bool ret = true;

    maid_hash *h = maid_hash_new(def);
    if (h)
    {
        TEST_IMPORT(input_b,  input);
        TEST_IMPORT(output_b, output);

        if (ret)
        {
            TEST_EMPTY(output2_b, output);

            maid_hash_renew(h);
            maid_hash_update(h, input_b, sizeof(input_b));
            maid_hash_digest(h, output2_b);

            ret = maid_mem_cmp(output_b, output2_b, sizeof(output_b));
        }
    }
    else
        ret = false;
    maid_hash_del(h);

    return ret;
}


static bool
test_rng(struct maid_rng_def def, char *entropy, char *output)
{
    bool ret = true;

    TEST_EMPTY(empty, entropy);

    maid_rng *g = maid_rng_new(def, empty);
    if (g)
    {
        TEST_IMPORT(entropy_b, entropy);
        TEST_IMPORT(output_b,  output);

        if (ret)
        {
            TEST_EMPTY(result_b, output);
            maid_rng_renew(g, entropy_b);
            maid_rng_generate(g, result_b, sizeof(result_b));

            ret = maid_mem_cmp(result_b, output_b, sizeof(result_b));
        }
    }
    else
        ret = false;
    maid_rng_del(g);

    return ret;
}

static bool
test_rsa(char *public, char *private, char *input, char *output)
{
    bool ret = true;

    TEST_IMPORT(pub_b, public);
    TEST_IMPORT(prv_b, private);

    if (ret)
    {
        maid_rsa_public  *k  = maid_rsa_new(pub_b,   sizeof(pub_b));
        maid_rsa_private *k2 = maid_rsa_new2(prv_b, sizeof(prv_b));
        if (k && k2)
        {
            size_t size = 0;
            u8 *kk = NULL;
            u8 *kk2 = NULL;

            ret &= (bool)(kk  = maid_rsa_export(k,  &size));
            ret &= (size == sizeof(pub_b)) && (memcmp(kk, pub_b, size) == 0);
            ret &= (bool)(kk2 = maid_rsa_export2(k2, &size));
            ret &= (size == sizeof(prv_b)) && (memcmp(kk2, prv_b, size) == 0);

            size_t words = maid_rsa_size(k);
            size_t words2 = maid_rsa_size2(k2);
            ret &= (words  != 0);
            ret &= (words2 != 0);
            ret &= (words == words2);

            if (ret)
            {
                TEST_IMPORT_MP(words, im,  ib,  input)
                TEST_IMPORT_MP(words, im2, ib2, input)
                TEST_IMPORT_MP(words, om,  ob, output)

                ret &= maid_rsa_decrypt(k2, im);
                ret &= maid_mp_cmp(words, im, om) == 0;
                ret &= maid_rsa_encrypt(k, om);
                ret &= maid_mp_cmp(words, im2, om) == 0;
            }
        }
        else
            ret = false;

        maid_rsa_del(k);
        maid_rsa_del2(k2);
    }

    return ret;
}

static bool
test_rsa2(void)
{
    bool ret = true;

    u8 entropy[32] = {0};
    maid_rng *g = maid_rng_new(maid_ctr_drbg_aes_128, entropy);
    if (g)
    {
        maid_rsa_private *k = maid_rsa_keygen(512, 65537, g);
        maid_rsa_public *k2 = maid_rsa_pubgen(k);
        ret = (k && k2 && maid_rsa_pair(k2, k));
    }
    else
        ret = false;
    free(g);

    return ret;
}

static bool
test_ecc(struct maid_ecc_def def, size_t words, char *base, char *inf,
         char *doub, char *trip, char *scalar, char *mul)
{
    bool ret = true;

    TEST_IMPORT_MP(words, sm, sb, scalar)
    TEST_IMPORT(bb, base)
    TEST_IMPORT(ib, inf)
    TEST_IMPORT(mb, mul)
    TEST_IMPORT(db, doub)
    TEST_IMPORT(rb, trip)
    TEST_EMPTY(tb, base)

    if (ret)
    {
        maid_ecc *c = maid_ecc_new(def);
        maid_ecc_point *r0 = maid_ecc_alloc(c);
        maid_ecc_point *r1 = maid_ecc_alloc(c);
        maid_ecc_point *r2 = maid_ecc_alloc(c);
        if (c && r0 && r1 && r2)
        {
            maid_ecc_base(c, r0);
            maid_ecc_copy(c, r1, NULL);
            maid_ecc_copy(c, r2, r0);

            ret = maid_ecc_encode(c, tb, r2);
            ret &= maid_mem_cmp(tb, bb, sizeof(tb));
            ret &= maid_ecc_encode(c, tb, r1);
            ret &= maid_mem_cmp(tb, ib, sizeof(tb));
            ret &= maid_ecc_decode(c, bb, r1);
            ret &= maid_ecc_encode(c, tb, r1);
            ret &= maid_mem_cmp(tb, bb, sizeof(tb));

            if (ret && maid_ecc_decode(c, bb, r0))
            {
                maid_ecc_dbl(c, r0);
                ret = maid_ecc_encode(c, tb, r0) &&
                      maid_mem_cmp(tb, db, sizeof(tb));
            }

            if (ret && maid_ecc_decode(c, bb, r1))
            {
                maid_ecc_add(c, r0, r1);
                ret = maid_ecc_encode(c, tb, r0) &&
                      maid_mem_cmp(tb, rb, sizeof(tb));
            }

            if (ret && maid_ecc_decode(c, bb, r0))
            {
                maid_ecc_mul(c, r0, sm, false);
                ret = maid_ecc_encode(c, tb, r0) &&
                      maid_mem_cmp(tb, mb, sizeof(tb));
            }

            if (ret && maid_ecc_decode(c, bb, r2))
            {
                maid_ecc_mul(c, r2, sm, true);
                ret = maid_ecc_encode(c, tb, r2) &&
                      maid_mem_cmp(tb, mb, sizeof(tb));
            }
        }
        else
            ret = false;
        maid_ecc_free(c, r0);
        maid_ecc_free(c, r1);
        maid_ecc_free(c, r2);
        maid_ecc_del(c);
    }

    return ret;
}

static bool
test_pem(const char *input, size_t items,
         enum maid_pem_t *type, char **data, char **export)
{
    bool ret = true;

    const char *current = input;
    const char *endptr = NULL;
    size_t i = 0;
    do
    {
        struct maid_pem *p = maid_pem_import(current, &endptr);

        if (p && i < items)
        {
            TEST_IMPORT(db, data[i]);
            ret = p->type == type[i] &&
                  maid_mem_cmp(p->data, db, sizeof(db)) &&
                  p->size == sizeof(db);

            if (ret)
            {
                char *str = maid_pem_export(p);
                if (str)
                    ret = (strcmp(str, export[i]) == 0);
                free(str);
            }
        }
        else
        {
            ret = false;
            break;
        }

        maid_pem_free(p);

        current = endptr;
        i++;
    } while (endptr && *endptr != '\0');

    return ret;
}

static bool
test_spki(enum maid_spki type, char *input, char *output)
{
    bool ret = true;

    TEST_IMPORT(ib, input)
    TEST_IMPORT(ob, output)

    if (ret)
    {
        u8 *stream = NULL;
        size_t length = 0;

        ret &= (type == maid_spki_import(ib, sizeof(ib), &stream, &length));
        ret &= (length == sizeof(ob));
        ret &= maid_mem_cmp(stream, ob, sizeof(ob));

        ret &= (maid_spki_export(type, ob, sizeof(ob), &stream, &length));
        ret &= (length == sizeof(ib));
        ret &= maid_mem_cmp(stream, ib, sizeof(ib));
        free(stream);
    }

    return ret;
}

static bool
test_pkcs8(enum maid_pkcs8 type, char *input, char *output)
{
    bool ret = true;

    TEST_IMPORT(ib, input)
    TEST_IMPORT(ob, output)

    if (ret)
    {
        u8 *stream = NULL;
        size_t length = 0;

        ret &= (type == maid_pkcs8_import(ib, sizeof(ib), &stream, &length));
        ret &= (length == sizeof(ob));
        ret &= maid_mem_cmp(stream, ob, sizeof(ob));

        ret &= (maid_pkcs8_export(type, ob, sizeof(ob), &stream, &length));
        ret &= (length == sizeof(ib));
        ret &= maid_mem_cmp(stream, ib, sizeof(ib));
        free(stream);
    }

    return ret;
}

static bool
test_pkcs1_v1_5(struct maid_sign_def def,
                char *public, char *private, char *input, char *output)
{
    bool ret = true;

    TEST_IMPORT(pub_b, public)
    TEST_IMPORT(prv_b, private)
    TEST_IMPORT(ib,    input)
    TEST_IMPORT(ob,    output)

    if (ret)
    {
        maid_rsa_public  *pub = maid_rsa_new(pub_b, sizeof(pub_b));
        maid_rsa_private *prv = maid_rsa_new2(prv_b, sizeof(prv_b));

        maid_sign *s = maid_sign_new(def, pub, prv);

        if (pub && prv && s)
        {
            size_t hash_s = 0;
            size_t sign_s = 0;
            ret = (maid_sign_size(s, &hash_s, &sign_s) &&
                   hash_s && hash_s == sizeof(ib) &&
                   sign_s && sign_s == sizeof(ob));

            if (ret)
            {
                u8 sign[sign_s];
                ret = maid_sign_generate(s, ib, sign)    &&
                      maid_mem_cmp(sign, ob, sizeof(ob)) &&
                      maid_sign_verify(s, ib, sign) &&
                     !maid_sign_verify(s, ob, sign);
            }
        }
        else
            ret = false;

        maid_rsa_del(pub);
        maid_rsa_del2(prv);
        maid_sign_del(s);
    }

    return ret;
}

static bool
test_dh(size_t bits, char *g, char *p,
        char *prv, char *pub, char *pub2, char *secret)
{
    bool ret = true;

    u8 zeros[bits / 8];
    struct maid_dh_group zgroup = {.generator = (void *)zeros,
                                   .modulo    = (void *)zeros};

    maid_kex *x = maid_kex_new(maid_dh, &zgroup, bits);

    if (x)
    {
        size_t words = maid_mp_words(bits);
        TEST_IMPORT_MP(words, gm, gb, g)
        TEST_IMPORT_MP(words, pm, pb, p)

        TEST_IMPORT(rb, prv)
        TEST_IMPORT(ub, pub)
        TEST_IMPORT(vb, pub2)
        TEST_IMPORT(sb, secret)

        TEST_EMPTY(bb, pub)
        if (ret)
        {
            struct maid_dh_group group = {.generator = gm, .modulo = pm};
            maid_kex_renew(x, &group);

            maid_kex_gpub(x, rb, bb);
            ret = maid_mem_cmp(bb, ub, sizeof(bb));
        }

        if (ret)
        {
            maid_kex_gsec(x, rb, vb, bb);
            ret = maid_mem_cmp(bb, sb, sizeof(bb));
        }
    }
    else
        ret = false;

    maid_kex_del(x);

    return ret;
}

/* Implemented tests */

extern u8
maid_test_mem(void)
{
    u8 ret = 26;

    u8 mem[24] = {0x00, 0x00, 0x00, 0x00, 0xb0, 0x0b, 0x00, 0x00};

    maid_mem_write(mem, 3, sizeof(u8),  false, 0xef);
    maid_mem_write(mem, 3, sizeof(u32), false, 0x0df0ad0b);
    maid_mem_write(mem, 2, sizeof(u64), true,  0xdec03713edacef0d);

    ret -= (maid_mem_read(mem, 3, sizeof(u8),  true)   == 0xef);
    ret -= (maid_mem_read(mem, 2, sizeof(u16), false)  == 0x0bb0);
    ret -= (maid_mem_read(mem, 3, sizeof(u32), true)   == 0x0badf00d);
    ret -= (maid_mem_read(mem, 2, sizeof(u64), false)  == 0x0defaced1337c0de);

    maid_mem_clear(mem, sizeof(mem));
    for (size_t i = 0; i < sizeof(mem); i++)
    {
        if (mem[i] != 0x0)
        {
            ret++;
            break;
        }
    }

    u8 zeros[24] = {0};
    ret -= maid_mem_cmp(mem, zeros, sizeof(mem));
    zeros[23] = 1;
    ret -= !maid_mem_cmp(mem, zeros, sizeof(mem));
    ret -= maid_mem_cmp(mem, zeros, 0);
    ret -= maid_mem_cmp(NULL, NULL, sizeof(mem));

    /* From RFC 4648 */
    char *base64[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==",
                      "Zm9vYmE=", "Zm9vYmFy"};
    char  *ascii[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};

    for (size_t i = 0; i < 7; i++)
    {
        ret -= test_mem_import(MAID_BASE64, base64[i], ascii[i]);
        ret -= test_mem_export(MAID_BASE64, ascii[i], base64[i]);
    }

    char *bad64[] = {"Zm9vYg", "Zm9vY%", "Zm9vY=Fy", "Zm9vYm=y"};
    for (size_t i = 0; i < 4; i++)
        ret -= !test_mem_import(MAID_BASE64, bad64[i], ascii[6]);

    return ret;
}

extern u8
maid_test_mp(void)
{
    u8 ret = 26;

    size_t words = maid_mp_words(256);
    ret -= (words == 4);

    char *sa = "c0d1f1ed0011b1d0cafebabe0de1f1ed"
               "11b1d0dec0d1f1eddeadbea7cafebe7a";
    char *sb = "deadc0dedeadfacebeefbabe0badcafe"
               "0bea57facaded003ed11b1d00badbea7";

    ret -= test_mp_rw(words, sa,
           "7abefecaa7beaddeedf1d1c0ded0b111edf1e10dbebafecad0b11100edf1d1c0");

    ret -= test_mp_not(words, sa);

    ret -= test_mp_a(words, maid_mp_and, sa, sb, false,
           "c081c0cc0001b0c08aeebabe09a1c0ec01a050dac0d0d001cc01b0800aacbe22");
    ret -= test_mp_a(words, maid_mp_orr, sa, sb, false,
           "defdf1ffdebdfbdefeffbabe0fedfbff1bfbd7fecadff1efffbdbff7cbffbeff");
    ret -= test_mp_a(words, maid_mp_xor, sa, sb, false,
           "1e7c3133debc4b1e74110000064c3b131a5b87240a0f21ee33bc0f77c15300dd");

    ret -= test_mp_cmp(words, sb, sa);

    ret -= test_mp_a(words, maid_mp_mov, sa, sb, true, sb);
    ret -= test_mp_a(words, maid_mp_add, sa, sb, false,
           "9f7fb2cbdebfac9f89ee757c198fbceb1d9c28d98bb0c1f1cbbf7077d6ac7d21");
    ret -= test_mp_a(words, maid_mp_sub, sa, sb, false,
           "e224310e2163b7020c0f0000023426ef05c778e3f5f321e9f19c0cd7bf50ffd3");

    ret -= test_mp_s(words, maid_mp_shl, sa, 33, true,
           "002363a195fd757c1bc3e3da2363a1bd81a3e3dbbd5b7d4f95fd7cf400000000");
    ret -= test_mp_s(words, maid_mp_shr, sa, 45, true,
           "000000000006068f8f68008d8e8657f5d5f06f0f8f688d8e86f6068f8f6ef56d");
    ret -= test_mp_s(words, maid_mp_sal, sa, 33, true,
           "002363a195fd757c1bc3e3da2363a1bd81a3e3dbbd5b7d4f95fd7cf400000000");
    ret -= test_mp_s(words, maid_mp_sar, sb, 45, false,
           "fffffffffffef56e06f6f56fd675f77dd5f05d6e57f05f52bfd656f6801f688d");

    char *sc = "0000000000000000000000000000cafe"
               "0bea57facaded003ed11b1d00badbea7";

    ret -= test_mp_a(words, maid_mp_mul, sa, sb, false,
           "0c38d648e0ed7643ad6b5926892d84e50348a8372c6ee86aecbc259473fecd96");
    ret -= test_mp_a(words, maid_mp_div, sa, sc, false,
           "000000000000000000000000000000000000f32be2eeb4f644355ea6504049ca");
    ret -= test_mp_a(words, maid_mp_mod, sa, sc, true,
           "0000000000000000000000000000c692e50b7de98c6b00f5181bf3dc2ec8afb4");
    ret -= test_mp_a(words, maid_mp_exp, sc, sa, false,
           "4e0e63adabf8dc0f6b299b04688b3f0f053bc6ae96423face4bf8e604e95df31");

    ret -= test_mp_div2(words, sa, sc,
           "000000000000000000000000000000000000f32be2eeb4f644355ea6504049ca",
           "0000000000000000000000000000c692e50b7de98c6b00f5181bf3dc2ec8afb4");

    ret -= test_mp_mulmod(words, sa, sb, sc,
           "0000000000000000000000000000ba47a813183a1a03729a545e69650ea7ec62");
    ret -= test_mp_expmod(words, maid_mp_expmod, sa, sb, sc,
           "00000000000000000000000000007960d37277127c408fae6d25702001a96c32");
    ret -= test_mp_invmod(words, sa, sb, sc,
           "00000000000000000000000000007823344d5d3621c25936272b9a68c0bcdd99");
    ret -= test_mp_expmod(words, maid_mp_expmod2, sa, sb, sc,
           "00000000000000000000000000007960d37277127c408fae6d25702001a96c32");

    /* Generators */
    u8 entropy[32] = {0};
    maid_rng *g = maid_rng_new(maid_ctr_drbg_aes_128, entropy);

    ret -= test_mp_random(words, g, 2, 7);
    ret -= test_mp_random2(words, g, sa, sb, 2, 7);
    ret -= test_mp_prime(words, g);

    maid_rng_del(g);

    return ret;
}

extern u8
maid_test_aes_ecb(void)
{
    /* AES NIST SP 800-38A vectors */

    u8 ret = 24;

    char key128[] = "2b7e151628aed2a6abf7158809cf4f3c";
    char key192[] = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    char key256[] = "603deb1015ca71be2b73aef0857d7781"
                    "1f352c073b6108d72d9810a30914dff4";

    char *block[] = {"6bc1bee22e409f96e93d7e117393172a",
                     "ae2d8a571e03ac9c9eb76fac45af8e51",
                     "30c81c46a35ce411e5fbc1191a0a52ef",
                     "f69f2445df4f9b17ad2b417be66c3710"};

    char *cipher128[] = {"3ad77bb40d7a3660a89ecaf32466ef97",
                         "f5d3d58503b9699de785895a96fdbaaf",
                         "43b1cd7f598ece23881b00e3ed030688",
                         "7b0c785e27e8ad3f8223207104725dd4"};
    char *cipher192[] = {"bd334f1d6e45f25ff712a214571fa5cc",
                         "974104846d0ad3ad7734ecb3ecee4eef",
                         "ef7afd2270e2e60adce0ba2face6444e",
                         "9a4b41ba738d6c72fb16691603c18e0e"};
    char *cipher256[] = {"f3eed1bdb5d2a03c064b5a7e3db181f8",
                         "591ccb10d410ed26dc5ba74a31362870",
                         "b6ed21b99ca6f4f9f153e7b1beafed1d",
                         "23304b7a39f9f3ff067d8d8f9e24ecc7"};

    for (u8 i = 0; i < 4; i++)
    {
        ret -= test_ecb(maid_aes_128, key128, block[i], cipher128[i], false);
        ret -= test_ecb(maid_aes_128, key128, cipher128[i], block[i], true);

        ret -= test_ecb(maid_aes_192, key192, block[i], cipher192[i], false);
        ret -= test_ecb(maid_aes_192, key192, cipher192[i], block[i], true);

        ret -= test_ecb(maid_aes_256, key256, block[i], cipher256[i], false);
        ret -= test_ecb(maid_aes_256, key256, cipher256[i], block[i], true);
    }

    return ret;
}

extern u8
maid_test_aes_ctr(void)
{
    /* AES-CTR NIST SP 800-38A vectors */

    u8 ret = 6;

    char key128[] = "2b7e151628aed2a6abf7158809cf4f3c";
    char key192[] = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    char key256[] = "603deb1015ca71be2b73aef0857d7781"
                    "1f352c073b6108d72d9810a30914dff4";

    char    iv[] = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    char block[] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
                   "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
                   "417be66c3710";

    char cipher128[] = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff861718"
                       "7bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe"
                       "03d1792170a0f3009cee";
    char cipher192[] = "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2"
                       "c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d298"
                       "09585a97daec58c6b050";
    char cipher256[] = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e9"
                       "90cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67a"
                       "ada613c2dd08457941a6";

    ret -= test_ctr(maid_aes_128, key128, iv, block, cipher128);
    ret -= test_ctr(maid_aes_128, key128, iv, cipher128, block);

    ret -= test_ctr(maid_aes_192, key192, iv, block, cipher192);
    ret -= test_ctr(maid_aes_192, key192, iv, cipher192, block);

    ret -= test_ctr(maid_aes_256, key256, iv, block, cipher256);
    ret -= test_ctr(maid_aes_256, key256, iv, cipher256, block);

    return ret;
}

extern u8
maid_test_aes_gcm(void)
{
    /* AES-GCM GCM Spec vectors */

    u8 ret = 12;

    char key_z[] = "00000000000000000000000000000000"
                   "00000000000000000000000000000000";
    char   key[] = "feffe9928665731c6d6a8f9467308308"
                   "feffe9928665731c6d6a8f9467308308";

    char  iv_z[] = "000000000000000000000000";
    char iv_96[] = "cafebabefacedbaddecaf888";

    char     ad[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    char  *data_z = "00000000000000000000000000000000";
    char   data[] = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8"
                    "a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba"
                    "637b391aafd255";
    char data_s[] = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8"
                    "a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba"
                    "637b39";

    char *cipher128[] = {"0388dace60b6a392f328c2b971b2fe78",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d51"
        "4b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d51"
        "4b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806"
        "900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a"
        "9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5"};
    char *tag128[] = {"58e2fccefa7e3061367f1d57a4e7455a",
                      "ab6e47d42cec13bdf53a67b21257bddf",
                      "4d5c2af327cd64a62cf35abd2ba6fab4",
                      "5bc94fbc3221a5db94fae95ae7121a47",
                      "3612d2e79e3b0785561be14aaca2fccb",
                      "619cc5aefffe0bfa462af43c1699d050"};
    char *cipher192[] = {"98e7247c07f0fe411c267e4384b0f600",
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773"
        "d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773"
        "d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc2"
        "9df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79"
        "012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b"};
    char *tag192[] = {"cd33b28ac773f74ba00ed1f312572435",
                      "2ff58d80033927ab8ef4d4587514f0fb",
                      "9924a7c8587336bfb118024db8674a14",
                      "2519498e80f1478f37ba55bd6d27618c",
                      "65dcc57fcf623a24094fcca40d3533f8",
                      "dcf566ff291c25bbb8568fc3d376a6d9"};
    char *cipher256[] = {"cea7403d4d606b6e074ec5d3baf39d18",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08"
        "e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08"
        "e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb58"
        "2d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c"
        "3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f"};
    char *tag256[] = {"530f8afbc74536b9a963b4f1c4cb738b",
                      "d0d1c8a799996bf0265b98b5d48ab919",
                      "b094dac5d93471bdec1a502270e3cc6c",
                      "76fc6ece0f4e1768cddf8853bb2d551b",
                      "3a337dbf46a792c45e454913fe2ea8f2",
                      "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"};

    char **ciphers[] = {cipher128, cipher192, cipher256};
    char    **tags[] = {tag128, tag192, tag256};

    struct maid_aead_def defs[] = {maid_aes_gcm_128,
                                   maid_aes_gcm_192,
                                   maid_aes_gcm_256};
    for (u8 i = 0; i < 3; i++)
    {
        ret -= test_aead(defs[i], key_z, iv_z,  "", "",
                         "",            tags[i][0], false);
        ret -= test_aead(defs[i], key_z, iv_z,  "", data_z,
                         ciphers[i][0], tags[i][1], false);
        ret -= test_aead(defs[i], key,   iv_96, "", data,
                         ciphers[i][1], tags[i][2], false),
        ret -= test_aead(defs[i], key,   iv_96, ad, data_s,
                         ciphers[i][2], tags[i][3], false);
    }

    return ret;
}

extern u8
maid_test_chacha(void)
{
    /* Chacha20 RFC8439 vectors */

    u8 ret = 11;

    char key_z[] = "00000000000000000000000000000000"
                   "00000000000000000000000000000000";
    char key_1[] = "00000000000000000000000000000000"
                   "00000000000000000000000000000001";
    char key_f[] = "00ff0000000000000000000000000000"
                   "00000000000000000000000000000000";
    char key_s[] = "000102030405060708090a0b0c0d0e0f"
                   "101112131415161718191a1b1c1d1e1f";
    char key_r[] = "1c9240a5eb55d38af333888604f6b5f0"
                   "473917c1402b80099dca5cbc207075c0";

    char nonce_z[] = "000000000000000000000000";
    char nonce_2[] = "000000000000000000000002";
    char nonce_a[] = "000000000000004a00000000";

    char data_zs[] = "00000000000000000000000000000000000000000000000000000000"
                     "00000000";
    char data_zb[] = "00000000000000000000000000000000000000000000000000000000"
                     "00000000000000000000000000000000000000000000000000000000"
                     "0000000000000000";
    char data_b1[] = "4c616469657320616e642047656e746c656d656e206f662074686520"
                     "636c617373206f66202739393a204966204920636f756c64206f6666"
                     "657220796f75206f6e6c79206f6e652074697020666f722074686520"
                     "6675747572652c2073756e73637265656e20776f756c642062652069"
                     "742e";
    char data_b2[] = "2754776173206272696c6c69672c20616e642074686520736c697468"
                     "7920746f7665730a446964206779726520616e642067696d626c6520"
                     "696e2074686520776162653a0a416c6c206d696d7379207765726520"
                     "74686520626f726f676f7665732c0a416e6420746865206d6f6d6520"
                     "7261746873206f757467726162652e";
    char data_b3[] = "416e79207375626d697373696f6e20746f2074686520494554462069"
                     "6e74656e6465642062792074686520436f6e7472696275746f722066"
                     "6f72207075626c69636174696f6e20617320616c6c206f7220706172"
                     "74206f6620616e204945544620496e7465726e65742d447261667420"
                     "6f722052464320616e6420616e792073746174656d656e74206d6164"
                     "652077697468696e2074686520636f6e74657874206f6620616e2049"
                     "45544620616374697669747920697320636f6e736964657265642061"
                     "6e20224945544620436f6e747269627574696f6e222e205375636820"
                     "73746174656d656e747320696e636c756465206f72616c2073746174"
                     "656d656e747320696e20494554462073657373696f6e732c20617320"
                     "77656c6c206173207772697474656e20616e6420656c656374726f6e"
                     "696320636f6d6d756e69636174696f6e73206d61646520617420616e"
                     "792074696d65206f7220706c6163652c207768696368206172652061"
                     "646472657373656420746f";
    char *ciphers[] = {"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27af"
                       "ccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e651"
                       "52ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52"
                       "bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eed"
                       "f2785e42874d",
                       "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836ef"
                       "cc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518"
                       "a11cc387b669b2ee6586",
                       "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c653"
                       "3e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510a"
                       "fb45ace10a1f4b794d6f",
                       "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284"
                       "f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b3"
                       "6125a64addeb006c13a0",
                       "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbe"
                       "a1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545"
                       "ec1b7374f4872e99f096",
                       "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab76"
                       "5b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e814"
                       "8362fa198a39531bed6d",
                       "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c"
                       "1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7"
                       "c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20"
                       "b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b329"
                       "1ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72"
                       "d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2"
                       "d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49e"
                       "b2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c76"
                       "5989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be05"
                       "9c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f8812"
                       "8cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36f"
                       "f216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759"
                       "c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1"
                       "ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
                       "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118eff"
                       "a95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65"
                       "b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a"
                       "5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b"
                       "6da731b187b58dfd728afa36757a797ac188d1",
                       "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836ef"
                       "cc8b770dc7",
                       "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666"
                       "dde3fbb739",
                       "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59de"
                       "aad23310ae"};

    char   *keys[] = {key_s, key_z, key_z, key_1, key_f, key_z, key_1,
                      key_r, key_z, key_1, key_r};
    char *nonces[] = {nonce_a, nonce_z, nonce_z, nonce_z, nonce_z, nonce_2,
                      nonce_2, nonce_2, nonce_z, nonce_2, nonce_2};
    char  *datas[] = {data_b1, data_zb, data_zb, data_zb, data_zb, data_zb,
                      data_b3, data_b2, data_zs, data_zs, data_zs};
    int counters[] = {1, 0, 1, 1, 2, 0, 1, 42, 0, 0, 0};

    for (u8 i = 0; i < 11; i++)
        ret -= test_stream(maid_chacha20, keys[i], nonces[i], counters[i],
                                datas[i], ciphers[i]);

    return ret;
}

extern u8
maid_test_poly1305(void)
{
    /* Poly1305 RFC8439 vectors */

    u8 ret = 11;

    char *keys[] = {"00000000000000000000000000000000"
                    "00000000000000000000000000000000",
                    "00000000000000000000000000000000"
                    "36e5f6b5c5e06070f0efca96227a863e",
                    "36e5f6b5c5e06070f0efca96227a863e"
                    "00000000000000000000000000000000",
                    "1c9240a5eb55d38af333888604f6b5f0"
                    "473917c1402b80099dca5cbc207075c0",
                    "02000000000000000000000000000000"
                    "00000000000000000000000000000000",
                    "02000000000000000000000000000000"
                    "ffffffffffffffffffffffffffffffff",
                    "01000000000000000000000000000000"
                    "00000000000000000000000000000000",
                    "01000000000000000000000000000000"
                    "00000000000000000000000000000000",
                    "02000000000000000000000000000000"
                    "00000000000000000000000000000000",
                    "01000000000000000400000000000000"
                    "00000000000000000000000000000000",
                    "01000000000000000400000000000000"
                    "00000000000000000000000000000000"};

    char *datas[] = {"00000000000000000000000000000000000000000000000000000000"
                     "00000000000000000000000000000000000000000000000000000000"
                     "00000000000000000000000000000000000000000000000000000000"
                     "00000000000000000000000000000000000000000000000000000000"
                     "00000000000000000000000000000000",
                     "416e79207375626d697373696f6e20746f2074686520494554462069"
                     "6e74656e6465642062792074686520436f6e7472696275746f722066"
                     "6f72207075626c69636174696f6e20617320616c6c206f7220706172"
                     "74206f6620616e204945544620496e7465726e65742d447261667420"
                     "6f722052464320616e6420616e792073746174656d656e74206d6164"
                     "652077697468696e2074686520636f6e74657874206f6620616e2049"
                     "45544620616374697669747920697320636f6e736964657265642061"
                     "6e20224945544620436f6e747269627574696f6e222e205375636820"
                     "73746174656d656e747320696e636c756465206f72616c2073746174"
                     "656d656e747320696e20494554462073657373696f6e732c20617320"
                     "77656c6c206173207772697474656e20616e6420656c656374726f6e"
                     "696320636f6d6d756e69636174696f6e73206d61646520617420616e"
                     "792074696d65206f7220706c6163652c207768696368206172652061"
                     "646472657373656420746f",
                     "416e79207375626d697373696f6e20746f2074686520494554462069"
                     "6e74656e6465642062792074686520436f6e7472696275746f722066"
                     "6f72207075626c69636174696f6e20617320616c6c206f7220706172"
                     "74206f6620616e204945544620496e7465726e65742d447261667420"
                     "6f722052464320616e6420616e792073746174656d656e74206d6164"
                     "652077697468696e2074686520636f6e74657874206f6620616e2049"
                     "45544620616374697669747920697320636f6e736964657265642061"
                     "6e20224945544620436f6e747269627574696f6e222e205375636820"
                     "73746174656d656e747320696e636c756465206f72616c2073746174"
                     "656d656e747320696e20494554462073657373696f6e732c20617320"
                     "77656c6c206173207772697474656e20616e6420656c656374726f6e"
                     "696320636f6d6d756e69636174696f6e73206d61646520617420616e"
                     "792074696d65206f7220706c6163652c207768696368206172652061"
                     "646472657373656420746f",
                     "2754776173206272696c6c69672c20616e642074686520736c697468"
                     "7920746f7665730a446964206779726520616e642067696d626c6520"
                     "696e2074686520776162653a0a416c6c206d696d7379207765726520"
                     "74686520626f726f676f7665732c0a416e6420746865206d6f6d6520"
                     "7261746873206f757467726162652e",
                     "ffffffffffffffffffffffffffffffff",
                     "02000000000000000000000000000000",
                     "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffff"
                     "ffffffff11000000000000000000000000000000",
                     "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefe"
                     "fefefefe01010101010101010101010101010101",
                     "fdffffffffffffffffffffffffffffff",
                     "e33594d7505e43b900000000000000003394d7505e4379cd01000000"
                     "00000000000000000000000000000000000000000100000000000000"
                     "0000000000000000",
                     "e33594d7505e43b900000000000000003394d7505e4379cd01000000"
                     "0000000000000000000000000000000000000000"};

    char *tags[] = {"00000000000000000000000000000000",
                    "36e5f6b5c5e06070f0efca96227a863e",
                    "f3477e7cd95417af89a6b8794c310cf0",
                    "4541669a7eaaee61e708dc7cbcc5eb62",
                    "03000000000000000000000000000000",
                    "03000000000000000000000000000000",
                    "05000000000000000000000000000000",
                    "00000000000000000000000000000000",
                    "faffffffffffffffffffffffffffffff",
                    "14000000000000005500000000000000",
                    "13000000000000000000000000000000"};

    for (u8 i = 0; i < 11; i++)
        ret -= test_mac(maid_poly1305, keys[i], datas[i], tags[i]);

    return ret;
}

extern u8
maid_test_chacha20poly1305(void)
{
    /* Chacha20Poly1305 RFC8439 vectors */

    u8 ret = 2;

    char   *keys[] = {"808182838485868788898a8b8c8d8e8f"
                      "909192939495969798999a9b9c9d9e9f",
                      "1c9240a5eb55d38af333888604f6b5f0"
                      "473917c1402b80099dca5cbc207075c0"};
    char *nonces[] = {"070000004041424344454647",
                      "000000000102030405060708"};
    char    *ads[] = {"50515253c0c1c2c3c4c5c6c7",
                      "f33388860000000000004e91"};

    char  *inputs[] = {"4c616469657320616e642047656e746c656d656e206f6620746865"
                       "20636c617373206f66202739393a204966204920636f756c64206f"
                       "6666657220796f75206f6e6c79206f6e652074697020666f722074"
                       "6865206675747572652c2073756e73637265656e20776f756c6420"
                       "62652069742e",
                       "64a0861575861af460f062c79be643bd5e805cfd345cf389f10867"
                       "0ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b"
                       "0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114"
                       "ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e"
                       "2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d"
                       "46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf45"
                       "34d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f5"
                       "48271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a10"
                       "73a6727627097a1049e617d91d361094fa68f0ff77987130305bea"
                       "ba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"};
    char *outputs[] = {"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5"
                       "a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e06"
                       "0b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fa"
                       "b324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d265"
                       "86cec64b6116",
                       "496e7465726e65742d447261667473206172652064726166742064"
                       "6f63756d656e74732076616c696420666f722061206d6178696d75"
                       "6d206f6620736978206d6f6e74687320616e64206d617920626520"
                       "757064617465642c207265706c616365642c206f72206f62736f6c"
                       "65746564206279206f7468657220646f63756d656e747320617420"
                       "616e792074696d652e20497420697320696e617070726f70726961"
                       "746520746f2075736520496e7465726e65742d4472616674732061"
                       "73207265666572656e6365206d6174657269616c206f7220746f20"
                       "63697465207468656d206f74686572207468616e206173202fe280"
                       "9c776f726b20696e2070726f67726573732e2fe2809d"};

    char *tags[] = {"1ae10b594f09e26a7e902ecbd0600691",
                    "eead9d67890cbb22392336fea1851f38"};
    bool modes[] = {false, true};

    for (u8 i = 0; i < 2; i++)
        ret -= test_aead(maid_chacha20poly1305, keys[i], nonces[i],
                         ads[i], inputs[i], outputs[i], tags[i], modes[i]);

    return ret;
}

extern u8
maid_test_ctr_drbg(void)
{
    /* CTR-DRBG NIST CAVP vectors */

    u8 ret = 9;

    char *entropy128[] = {"ce50f33da5d4c1d3d4004eb35244b7f2"
                          "cd7f2e5076fbf6780a7ff634b249a5fc",
                          "a385f70a4d450321dfd18d8379ef8e77"
                          "36fee5fbf0a0aea53b76696094e8aa93",
                          "d4f47c385e5ee36915978386a074d413"
                          "d04a1ce3a13a0fe2b17f3f20f83a93fd"};
    char *entropy192[] = {"f1ef7eb311c850e189be229df7e6d68f"
                          "1795aa8e21d93504e75abe78f0413958"
                          "73540386812a9a2a",
                          "818d5b460cf0e18faf2441c97eef12eb"
                          "a4eca4be95a277c4f7ca904da1981cb9"
                          "05a290601db8b677",
                          "e45dc4113f01b589e503e7c58f6a7c91"
                          "0d8a3458b71fb322bbbfee175e15060b"
                          "278ae692fb39d46e"};
    char *entropy256[] = {"df5d73faa468649edda33b5cca79b0b0"
                          "5600419ccb7a879ddfec9db32ee494e5"
                          "531b51de16a30f769262474c73bec010",
                          "3b6fb634d35bb386927374f991c1cbc9"
                          "fafba3a43c432dc411b7b2fa96cfcce8"
                          "d305e135ff9bc460dbc7ba3990bf8060",
                          "0217a8acf2f8e2c4ab7bdcd5a694bca2"
                          "8d038018869dcbe2160d1ce0b4c78ead"
                          "5592efed98662f2dff87f32f4835c677"};

    /* Second call result was calculated from the Key and V given */
    char *output128[] = {"6545c0529d372443b392ceb3ae3a99a3"
                         "0f963eaf313280f1d1a1e87f9db373d3"
                         "61e75d18018266499cccd64d9bbb8de0"
                         "185f213383080faddec46bae1f784e5a"
                         "9b61287a59ab17d5b11fce95eea40850"
                         "705608f5a6fad9be984c189a39c1b5a0"
                         "a5d33a5fa62812c8e5ef5c59643fd7c6"
                         "fcb29bdfc63c402cf33aa010f61f175d",
                         "1a062553ab60457ed1f1c52f5aca5a3b"
                         "e564a27545358c112ed92c6eae2cb759"
                         "7cfcc2e0a5dd81c5bfecc941da5e8152"
                         "a9010d4845170734676c8c1b6b3073a5"
                         "575542f1be776061d58eed37371e6798"
                         "5b769acba93af2b48e84648db6410f97"
                         "d2956ae08592a33b05bf36cf60fad9b6"
                         "dd4c6dd3f109bbb790ec1c9b50218d16",
                         "27f880df4c2907697fb2f594e311559c"
                         "ea827049327af31fa7f0cbf332c46206"
                         "74f503d7dc378320d228907151d32ee5"
                         "e3f5c5eccb13afe58bf6a60192e6d70e"
                         "1399934a7cd642d0115a4a5410d94da3"
                         "43030ec5f123605fe3c9ca6e9183f693"
                         "328d54aa71dbae936065cf2e73987ffe"
                         "4ee4a9b59c18a5f3933fa6079e849115"};
    char *output192[] = {"6bb0aa5b4b97ee83765736ad0e9068df"
                         "ef0ccfc93b71c1d3425302ef7ba4635f"
                         "fc09981d262177e208a7ec90a557b6d7"
                         "6112d56c40893892c3034835036d7a69"
                         "e409eb6a7c074b4b4785972a375cc237"
                         "ad7ec4f828c3c2bd3938ce998b53f713"
                         "4402d2884f52c20d2467f10649c48439"
                         "1f05990b9b3886b08b3c9557651226f8",
                         "6fd75498e5f38c40e72a0a3c2e2247ca"
                         "133931bfed4237f0c9a19f6bbf6ab838"
                         "1f9271337f6de6af53d7d5f67257fce6"
                         "bc8e602af8b9844f043c78f2d24e4ffb"
                         "68c2537a7c38dfea7f9194df3d18ad7a"
                         "55fa5abb78e9076d28a90ea70919f998"
                         "8943de40143baca544346696b3b282ef"
                         "63ee7b2e257f01b98161e885c1ba074c",
                         "65c696c8cd524977eaef54b5f7596f84"
                         "d9681efc7fee5a41c1479c04b18175e2"
                         "ec0296c9777ce460ebb6e2c506303142"
                         "0258391c70f5926be115035dd95155bb"
                         "6b4bbed4738769b6cb90ea1da9fb3ae0"
                         "25a35f330121c4705ab4b8329fff1dca"
                         "56db2e179ae14632234a537338559f23"
                         "a0364246bc877391b65ead081c96b114"};
    char *output256[] = {"d1c07cd95af8a7f11012c84ce48bb8cb"
                         "87189e99d40fccb1771c619bdf82ab22"
                         "80b1dc2f2581f39164f7ac0c510494b3"
                         "a43c41b7db17514c87b107ae793e01c5"
                         "cd66eaabef900f38e817f9211fbf522a"
                         "23ab7deafd003b30566ec7ac41aced66"
                         "35b9444f38e0acd56f8b1922364b9841"
                         "1ffa9317c6984d3130de0cb97c857cc2",
                         "083a836fe1cde053164555529409337d"
                         "c4fec6844594fdf15083ba9d1001eb94"
                         "5c3b96a1bcee3990e1e51f85c80e9f4e"
                         "04de34e57b640f6cae8ed68e99624712"
                         "ecdfe4681970e56e13428a174aca9de2"
                         "5c4ba2f28cf15d9f9a9c1f54a3b2e5f7"
                         "874064b05e470656e65f2541e3dc20a9"
                         "9b0df559158f5cfcc0036694cc37a9bd",
                         "aa36779726f52875312507fb084744d4"
                         "d7f3f9468a5b246ccde316d2ab91879c"
                         "2e29f5a0938a3bcd722bb718d01bbfc3"
                         "5831c9e64f5b6410ae908d3061f76c84"
                         "2dadf3fd6c886a0aaf707f8a28b4dcac"
                         "aa500f76758b246992375472be90fdfa"
                         "20646c3466bde247c0633153d23194cf"
                         "aca0772d1396209ec9e7506ba23d75dc"};

    for (u8 i = 0; i < 3; i++)
    {
        ret -= test_rng(maid_ctr_drbg_aes_128, entropy128[i], output128[i]);
        ret -= test_rng(maid_ctr_drbg_aes_192, entropy192[i], output192[i]);
        ret -= test_rng(maid_ctr_drbg_aes_256, entropy256[i], output256[i]);
    }

    return ret;
}

extern u8
maid_test_sha1(void)
{
    u8 ret = 2;

    char *input0 = "616263";
    char *input1 = "6162636462636465636465666465666765666768666768696768696a"
                   "68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";

    char *outputs0 = "a9993e364706816aba3e25717850c26c9cd0d89d";
    char *outputs1 = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

    ret -= test_hash(maid_sha1, input0, outputs0);
    ret -= test_hash(maid_sha1, input1, outputs1);

    return ret;
}

extern u8
maid_test_sha2(void)
{
    /* SHA-2 NIST CSRC examples */

    u8 ret = 12;

    char *input0 = "616263";
    char *input1 = "6162636462636465636465666465666765666768666768696768696a"
                   "68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
    char *input2 = "61626364656667686263646566676869636465666768696a64656667"
                   "68696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e"
                   "68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e"
                   "6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475";

    char *outputs0[] = {"23097d223405d8228642a477bda255b3"
                        "2aadbce4bda0b3f7e36c9da7",
                        "ba7816bf8f01cfea414140de5dae2223"
                        "b00361a396177a9cb410ff61f20015ad",
                        "cb00753f45a35e8bb5a03d699ac65007"
                        "272c32ab0eded1631a8b605a43ff5bed"
                        "8086072ba1e7cc2358baeca134c825a7",
                        "ddaf35a193617abacc417349ae204131"
                        "12e6fa4e89a97ea20a9eeee64b55d39a"
                        "2192992a274fc1a836ba3c23a3feebbd"
                        "454d4423643ce80e2a9ac94fa54ca49f",
                        "4634270f707b6a54daae7530460842e2"
                        "0e37ed265ceee9a43e8924aa",
                        "53048e2681941ef99b2e29b76b4c7dab"
                        "e4c2d0c634fc6d46e0e2f13107e7af23"};
    char *outputs1[] = {"75388b16512776cc5dba5da1fd890150"
                        "b0c6455cb4f58b1952522525",
                        "248d6a61d20638b8e5c026930c3e6039"
                        "a33ce45964ff2167f6ecedd419db06c1"};
    char *outputs2[] = {"09330c33f71147e83d192fc782cd1b47"
                        "53111b173b3b05d22fa08086e3b0f712"
                        "fcc7c71a557e2db966c3e9fa91746039",
                        "8e959b75dae313da8cf4f72814fc143f"
                        "8f7779c6eb9f7fa17299aeadb6889018"
                        "501d289e4900f7e4331b99dec4b5433a"
                        "c7d329eeb6dd26545e96e55b874be909",
                        "23fec5bb94d60b23308192640b0c4533"
                        "35d664734fe40e7268674af9",
                        "3928e184fb8690f840da3988121d31be"
                        "65cb9d3ef83ee6146feac861e19b563a"};

    struct maid_hash_def defs256[] = {maid_sha224, maid_sha256};

    for (u8 i = 0; i < 2; i++)
    {
        ret -= test_hash(defs256[i], input0, outputs0[i]);
        ret -= test_hash(defs256[i], input1, outputs1[i]);
    }

    struct maid_hash_def defs512[] = {maid_sha384,     maid_sha512,
                                      maid_sha512_224, maid_sha512_256};

    for (u8 i = 0; i < 4; i++)
    {
        ret -= test_hash(defs512[i], input0, outputs0[i + 2]);
        ret -= test_hash(defs512[i], input2, outputs2[i + 0]);
    }

    return ret;
}

extern u8
maid_test_hmac_sha1(void)
{
    /* HMAC RFC2202 test vectors */

    u8 ret = 1;

    char *key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000"
                "00000000000000000000000000000000000000000000000000000000"
                "0000000000000000";
    char *data = "4869205468657265";
    char *tag = "b617318655057264e28bc0b6fb378c8ef146be00";

    ret -= test_mac(maid_hmac_sha1, key, data, tag);

    return ret;
}

extern u8
maid_test_hmac_sha2(void)
{
    /* HMAC RFC4231 test vectors +
     * comparison with other implementations */

    u8 ret = 6;

    char *keys[] = {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                    "0000000000000000",
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                    "00000000000000000000000000000000000000000000000000000000"
                    "00000000000000000000000000000000"};
    char *data    = "4869205468657265";

    char *tags[] = {
                    "896fb1128abbdf196832107cd49df33f"
                    "47b4b1169912ba4f53684b22",
                    "b0344c61d8db38535ca8afceaf0bf12b"
                    "881dc200c9833da726e9376c2e32cff7",
                    "afd03944d84895626b0825f4ab46907f"
                    "15f9dadbe4101ec682aa034c7cebc59c"
                    "faea9ea9076ede7f4af152e8b2fa9cb6",
                    "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                    "2379f4e2ce4ec2787ad0b30545e17cde"
                    "daa833b7d6b8a702038b274eaea3f4e4"
                    "be9d914eeb61f1702e696c203a126854",
                    "b244ba01307c0e7a8ccaad13b1067a4c"
                    "f6b961fe0c6a20bda3d92039",
                    "9f9126c3d9c3c330d760425ca8a217e3"
                    "1feae31bfe70196ff81642b868402eab"};

    ret -= test_mac(maid_hmac_sha224,     keys[0], data, tags[0]);
    ret -= test_mac(maid_hmac_sha256,     keys[0], data, tags[1]);
    ret -= test_mac(maid_hmac_sha384,     keys[1], data, tags[2]);
    ret -= test_mac(maid_hmac_sha512,     keys[1], data, tags[3]);
    ret -= test_mac(maid_hmac_sha512_224, keys[1], data, tags[4]);
    ret -= test_mac(maid_hmac_sha512_256, keys[1], data, tags[5]);

    return ret;
}

extern u8
maid_test_rsa(void)
{
    /* Comparison with OpenSSL + sanity check */

    u8 ret = 2;

    char *public =
        "308201090282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7eb6e243"
        "66aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec33ef2a9"
        "9e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7fc463febf30"
        "299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c31941534257299"
        "d206911a4a8a6163e26f82737e126b3e682567e6627429e48104e25af999c8a8"
        "6e6e30f1399c8d7a608dc427de103644519914288594a69c495a86cf43b12e7f"
        "b0a002eb31d1f889b9ad451b45ee15e871204f48c9ecd35432b7c429bcdf6287"
        "c22b7b6aec4975b3b8d8207bd8d497abc01a4efb31f01a8cdb8a389d6ec3936e"
        "573dd34b25fe5a650203010001";
    char *private =
        "308204a10201000282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7e"
        "b6e24366aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec3"
        "3ef2a99e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7fc463"
        "febf30299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c31941534"
        "257299d206911a4a8a6163e26f82737e126b3e682567e6627429e48104e25af9"
        "99c8a86e6e30f1399c8d7a608dc427de103644519914288594a69c495a86cf43"
        "b12e7fb0a002eb31d1f889b9ad451b45ee15e871204f48c9ecd35432b7c429bc"
        "df6287c22b7b6aec4975b3b8d8207bd8d497abc01a4efb31f01a8cdb8a389d6e"
        "c3936e573dd34b25fe5a6502030100010282010033bad2fcc5e6e430f087d825"
        "3b8990fe996920f0fd0c862c76a0fd64591fca50e998866973ae11604198e5b3"
        "e597eb287a5daec39011e39f14856147df35802c1838ad8e3a4dc8485bd215d1"
        "6a8b73e47b6009256a3b58a056cc0c72bf5ea6cb5a9075da6fff3a1a3099c159"
        "69ea78ee4a5400118bbd29aabc3fe454b0acb8e9a275387ba927bb4512001b51"
        "f8525b87b5b4dbddd5f90e2b8416b796b791387737bb140f89fb6739face7857"
        "5c0fb9175757a02411d033c32f6ab9a869a7d8eed90be34dcada047d5d93b232"
        "15ea34827c9b2749860ea7ae4a3fc1aa349505fd1cde16ab3caea5b2782fff75"
        "e77230fd5dbcfb9df777310b2778bfb52cb778810281805c9e59874192f39cf9"
        "77f915cb9df43c55d5ea4d740d39175ee5270745e39a20edc70c4f0cc81b31d6"
        "435bac25f97b6a726a5916d8923b3dd67ac50a00a87547bc7ccb446bd0f36480"
        "bff4c38c2bb2412cc556cf92426a53f2adba28cbfacd96e9d0c4f067466443e6"
        "b5913eab24d16b400b2ebbeedc37bf374b7eb81de2feb102818100bb1ef08afa"
        "0e0f59f5b0b54213f79cc181fe33d1ae5e802fcee5cd9d857774848fe9cc457d"
        "1cca5ddfae7d7e72671240b6a010c9b2839912f2c93068a4ce18b2fc3eb75be8"
        "317beaea4edf23437a77f708c7e7e789aa4d941f15d1520b3570f69b76745a08"
        "b7f96df9575eb1b471a8cf699c7f54740c536160e3e88ec17f0bf50281801565"
        "cc1f508a07d85b565968acab28730c0da8dd0e13c3fddf41a7dba94ce51df871"
        "4529ba353cfb2d9a50429c5f6020fea00d4716efe9d9e68464a363f5876af464"
        "0c7e193ea40cb32626014b9008d5bfe733a02f154305740aa8f8a5efa2b1dc01"
        "0c8ed1fd544acfb161060e7a2a1bd227033c0dfa38b2e7ae7c6f43105f710281"
        "81009cd53cc52efa33d1b1842f17b8069442f802284a793c4972489601752255"
        "51ba7da87686536b9b0d7d1a11a2b69e3f05304c0e660f120f6d7b423729addf"
        "f381a8bba4110b16d686b965ebcdf193a712cd3047e59f53b6fc0be5cc705866"
        "ad4c74569f048b442f7206473d5df220455dba65e9aece293a8566a0fedd0fbe"
        "bd350281802d6b6e6718bbd8ea3ed0a15c30d724282368b719121a4414b57282"
        "32ba628294cfb20c21ae5fa8c50b5e529617e97b2048eb637a31b76e1ae3db6d"
        "a6b02ed9b49c460809fa00bc9533483c7c962dc076a58ef56163550bf98d1ae2"
        "c76cd31542e79a71a6d593c1944eb1860a9a544514f2a451f08a9898b36aeb1a"
        "bf23747952";

    char *input =
        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffff003031300d060960864801650304020105000420"
        "355cd8229d6d67a9fd82ff31a77d5636831a2fd8fc007e46487488e5213e5d7a";
    char *output =
        "2d432e7d7a187f8e2f3ad3706cfb711df47ba777dbcba7cc3b9bc501f0a5ad65"
        "0928ecb7422ebfc274953da5dad58facc9cde6589f00f0936039a4769727d917"
        "6ed83df226686782e27b2ecc6e34789bdbe842d829f322f496abff3a4d4bb1cd"
        "0aa6ed3f58fd5c60c17bb7c2fb0c250a2530b006f25c3c02cc04042b88de79e1"
        "0c2fbc77c7a36bd90cb0043006d4f73b36534e9d6f345fbae1c56b17daf04423"
        "882e8e95645e36fa3b73c4e433d600a46d76f0771343b1779de40e2168de54e6"
        "e5ea683baee16bc44f719535b9cbad367d47b6c58fb61ff01bc9658e7f0efee0"
        "5bc30ab176bb85af96ba7d66c713a52c05dddd0ad36df798437ed42fef5fd75d";

    ret -= test_rsa(public, private, input, output);
    ret -= test_rsa2();

    return ret;
}

extern u8
maid_test_edwards25519(void)
{
    return 1 - test_ecc(maid_edwards25519, maid_mp_words(256),
                        "58666666666666666666666666666666"
                        "66666666666666666666666666666666",
                        "01000000000000000000000000000000"
                        "00000000000000000000000000000000",
                        "c9a3f86aae465f0e56513864510f3997"
                        "561fa2c9e85ea21dc2292309f3cd6022",
                        "d4b4f5784868c3020403246717ec169f"
                        "f79e26608ea126a1ab69ee77d1b16712",
                        "4fe94d9006f020a5a3c080d96827fffd"
                        "3c010ac0f12e7a42cb33284f86837c30",
                        "d75a980182b10ab7d54bfed3c964073a"
                        "0ee172f3daa62325af021a68f707511a");
}

extern u8
maid_test_pem(void)
{
    /* PEM encoding RFC 7468 examples */

    u8 ret = 1;

    const char *full =
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe\n"
        "kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U\n"
        "Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp\n"
        "-----END PUBLIC KEY-----\n"
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "This is a test\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf\n"
        "jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK\n"
        "H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ\n"
        "-----END PRIVATE KEY-----\n";

    enum maid_pem_t type[] = {MAID_PEM_PUBLIC, MAID_PEM_PRIVATE};
    char *data[] = {
        "3076301006072a8648ce3d020106052b81040022036200049f52e5c0b37f281610"
        "4551fa1df20c4f37c4a89395ced2de90b721a76862efc70268c63cd4506562cf09"
        "f65ee4adcf8ce1a05e0866058db6be8625edb4958f2fbc9d944fb9506e143649f7"
        "128b3c122641ca2f4356cc9fcbd79e8e1fbc017829",
        "308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420"
        "55c07f50d3f16a547dcc36008d021f8e88d40e242e1a7489ac5104cd93d3ffdda1"
        "44034200049ced426d82717f69ba9633ad13dd734913306fe5ecfd4ddc0a1f433a"
        "c69336abee77c26b0dfde60b760b638017770c1987b4f8a50a48852025f2680f33"
        "f4b909"};
    char *export[] = {
        "-----BEGIN PUBLIC KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe\n"
        "kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U\n"
        "Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp\n"
        "-----END PUBLIC KEY-----\n",
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf\n"
        "jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK\n"
        "H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ\n"
        "-----END PRIVATE KEY-----\n"};

    ret -= test_pem(full, 2, type, data, export);

    return ret;
}

extern u8
maid_test_spki(void)
{
    /* Comparison with OpenSSL */

    u8 ret = 2;

    enum maid_spki type[] = {MAID_SPKI_RSA, MAID_SPKI_ED25519};
    char *input[] =
        {"30820121300d06092a864886f70d01010105000382010e00308201090282"
         "010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7eb6e24366aac85b"
         "7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec33ef2a99e23"
         "43012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7fc463febf30"
         "299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c3194153425"
         "7299d206911a4a8a6163e26f82737e126b3e682567e6627429e48104e25a"
         "f999c8a86e6e30f1399c8d7a608dc427de103644519914288594a69c495a"
         "86cf43b12e7fb0a002eb31d1f889b9ad451b45ee15e871204f48c9ecd354"
         "32b7c429bcdf6287c22b7b6aec4975b3b8d8207bd8d497abc01a4efb31f0"
         "1a8cdb8a389d6ec3936e573dd34b25fe5a650203010001",
         "302a300506032b657003210001b395a89ac5e4bfdbab4a7b5f0e9d078066"
         "f42b8e5b5b3fa59361d924d53ae8"};
    char *output[] =
        {"308201090282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7eb6"
         "e24366aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8e"
         "c33ef2a99e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee"
         "7fc463febf30299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f"
         "8c31941534257299d206911a4a8a6163e26f82737e126b3e682567e66274"
         "29e48104e25af999c8a86e6e30f1399c8d7a608dc427de10364451991428"
         "8594a69c495a86cf43b12e7fb0a002eb31d1f889b9ad451b45ee15e87120"
         "4f48c9ecd35432b7c429bcdf6287c22b7b6aec4975b3b8d8207bd8d497ab"
         "c01a4efb31f01a8cdb8a389d6ec3936e573dd34b25fe5a650203010001",
         "01b395a89ac5e4bfdbab4a7b5f0e9d078066f42b8e5b5b3fa59361d924d5"
         "3ae8"};

    for (u8 i = 0; i < 2; i++)
        ret -= test_spki(type[i], input[i], output[i]);

    return ret;
}

extern u8
maid_test_pkcs8(void)
{
    /* Comparison with OpenSSL */

    u8 ret = 2;

    enum maid_pkcs8 type[] = {MAID_PKCS8_RSA, MAID_PKCS8_ED25519};
    char *input[] =
        {"308204bb020100300d06092a864886f70d0101010500048204a5308204a1"
         "0201000282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7eb6e2"
         "4366aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec3"
         "3ef2a99e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7f"
         "c463febf30299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c"
         "31941534257299d206911a4a8a6163e26f82737e126b3e682567e6627429"
         "e48104e25af999c8a86e6e30f1399c8d7a608dc427de1036445199142885"
         "94a69c495a86cf43b12e7fb0a002eb31d1f889b9ad451b45ee15e871204f"
         "48c9ecd35432b7c429bcdf6287c22b7b6aec4975b3b8d8207bd8d497abc0"
         "1a4efb31f01a8cdb8a389d6ec3936e573dd34b25fe5a6502030100010282"
         "010033bad2fcc5e6e430f087d8253b8990fe996920f0fd0c862c76a0fd64"
         "591fca50e998866973ae11604198e5b3e597eb287a5daec39011e39f1485"
         "6147df35802c1838ad8e3a4dc8485bd215d16a8b73e47b6009256a3b58a0"
         "56cc0c72bf5ea6cb5a9075da6fff3a1a3099c15969ea78ee4a5400118bbd"
         "29aabc3fe454b0acb8e9a275387ba927bb4512001b51f8525b87b5b4dbdd"
         "d5f90e2b8416b796b791387737bb140f89fb6739face78575c0fb9175757"
         "a02411d033c32f6ab9a869a7d8eed90be34dcada047d5d93b23215ea3482"
         "7c9b2749860ea7ae4a3fc1aa349505fd1cde16ab3caea5b2782fff75e772"
         "30fd5dbcfb9df777310b2778bfb52cb778810281805c9e59874192f39cf9"
         "77f915cb9df43c55d5ea4d740d39175ee5270745e39a20edc70c4f0cc81b"
         "31d6435bac25f97b6a726a5916d8923b3dd67ac50a00a87547bc7ccb446b"
         "d0f36480bff4c38c2bb2412cc556cf92426a53f2adba28cbfacd96e9d0c4"
         "f067466443e6b5913eab24d16b400b2ebbeedc37bf374b7eb81de2feb102"
         "818100bb1ef08afa0e0f59f5b0b54213f79cc181fe33d1ae5e802fcee5cd"
         "9d857774848fe9cc457d1cca5ddfae7d7e72671240b6a010c9b2839912f2"
         "c93068a4ce18b2fc3eb75be8317beaea4edf23437a77f708c7e7e789aa4d"
         "941f15d1520b3570f69b76745a08b7f96df9575eb1b471a8cf699c7f5474"
         "0c536160e3e88ec17f0bf50281801565cc1f508a07d85b565968acab2873"
         "0c0da8dd0e13c3fddf41a7dba94ce51df8714529ba353cfb2d9a50429c5f"
         "6020fea00d4716efe9d9e68464a363f5876af4640c7e193ea40cb3262601"
         "4b9008d5bfe733a02f154305740aa8f8a5efa2b1dc010c8ed1fd544acfb1"
         "61060e7a2a1bd227033c0dfa38b2e7ae7c6f43105f71028181009cd53cc5"
         "2efa33d1b1842f17b8069442f802284a793c497248960175225551ba7da8"
         "7686536b9b0d7d1a11a2b69e3f05304c0e660f120f6d7b423729addff381"
         "a8bba4110b16d686b965ebcdf193a712cd3047e59f53b6fc0be5cc705866"
         "ad4c74569f048b442f7206473d5df220455dba65e9aece293a8566a0fedd"
         "0fbebd350281802d6b6e6718bbd8ea3ed0a15c30d724282368b719121a44"
         "14b5728232ba628294cfb20c21ae5fa8c50b5e529617e97b2048eb637a31"
         "b76e1ae3db6da6b02ed9b49c460809fa00bc9533483c7c962dc076a58ef5"
         "6163550bf98d1ae2c76cd31542e79a71a6d593c1944eb1860a9a544514f2"
         "a451f08a9898b36aeb1abf23747952",
         "302e020100300506032b65700422042057901fc2ff66f6ab2fdbb74d6ddc"
         "68c3bde29c9fa5be88893501355ddb1ccafd"};
    char *output[] =
        {"308204a10201000282010043b2dcfb0682d13422d8fa6ef324691aa55cc6"
         "5b7eb6e24366aac85b7a2afaa2cead22550de99822b1f73964437f8c82da"
         "edac8ec33ef2a99e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8ea"
         "be6dee7fc463febf30299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e"
         "536c1f8c31941534257299d206911a4a8a6163e26f82737e126b3e682567"
         "e6627429e48104e25af999c8a86e6e30f1399c8d7a608dc427de10364451"
         "9914288594a69c495a86cf43b12e7fb0a002eb31d1f889b9ad451b45ee15"
         "e871204f48c9ecd35432b7c429bcdf6287c22b7b6aec4975b3b8d8207bd8"
         "d497abc01a4efb31f01a8cdb8a389d6ec3936e573dd34b25fe5a65020301"
         "00010282010033bad2fcc5e6e430f087d8253b8990fe996920f0fd0c862c"
         "76a0fd64591fca50e998866973ae11604198e5b3e597eb287a5daec39011"
         "e39f14856147df35802c1838ad8e3a4dc8485bd215d16a8b73e47b600925"
         "6a3b58a056cc0c72bf5ea6cb5a9075da6fff3a1a3099c15969ea78ee4a54"
         "00118bbd29aabc3fe454b0acb8e9a275387ba927bb4512001b51f8525b87"
         "b5b4dbddd5f90e2b8416b796b791387737bb140f89fb6739face78575c0f"
         "b9175757a02411d033c32f6ab9a869a7d8eed90be34dcada047d5d93b232"
         "15ea34827c9b2749860ea7ae4a3fc1aa349505fd1cde16ab3caea5b2782f"
         "ff75e77230fd5dbcfb9df777310b2778bfb52cb778810281805c9e598741"
         "92f39cf977f915cb9df43c55d5ea4d740d39175ee5270745e39a20edc70c"
         "4f0cc81b31d6435bac25f97b6a726a5916d8923b3dd67ac50a00a87547bc"
         "7ccb446bd0f36480bff4c38c2bb2412cc556cf92426a53f2adba28cbfacd"
         "96e9d0c4f067466443e6b5913eab24d16b400b2ebbeedc37bf374b7eb81d"
         "e2feb102818100bb1ef08afa0e0f59f5b0b54213f79cc181fe33d1ae5e80"
         "2fcee5cd9d857774848fe9cc457d1cca5ddfae7d7e72671240b6a010c9b2"
         "839912f2c93068a4ce18b2fc3eb75be8317beaea4edf23437a77f708c7e7"
         "e789aa4d941f15d1520b3570f69b76745a08b7f96df9575eb1b471a8cf69"
         "9c7f54740c536160e3e88ec17f0bf50281801565cc1f508a07d85b565968"
         "acab28730c0da8dd0e13c3fddf41a7dba94ce51df8714529ba353cfb2d9a"
         "50429c5f6020fea00d4716efe9d9e68464a363f5876af4640c7e193ea40c"
         "b32626014b9008d5bfe733a02f154305740aa8f8a5efa2b1dc010c8ed1fd"
         "544acfb161060e7a2a1bd227033c0dfa38b2e7ae7c6f43105f7102818100"
         "9cd53cc52efa33d1b1842f17b8069442f802284a793c4972489601752255"
         "51ba7da87686536b9b0d7d1a11a2b69e3f05304c0e660f120f6d7b423729"
         "addff381a8bba4110b16d686b965ebcdf193a712cd3047e59f53b6fc0be5"
         "cc705866ad4c74569f048b442f7206473d5df220455dba65e9aece293a85"
         "66a0fedd0fbebd350281802d6b6e6718bbd8ea3ed0a15c30d724282368b7"
         "19121a4414b5728232ba628294cfb20c21ae5fa8c50b5e529617e97b2048"
         "eb637a31b76e1ae3db6da6b02ed9b49c460809fa00bc9533483c7c962dc0"
         "76a58ef56163550bf98d1ae2c76cd31542e79a71a6d593c1944eb1860a9a"
         "544514f2a451f08a9898b36aeb1abf23747952",
         "042057901fc2ff66f6ab2fdbb74d6ddc68c3bde29c9fa5be88893501355d"
         "db1ccafd"};

    for (u8 i = 0; i < 2; i++)
        ret -= test_pkcs8(type[i], input[i], output[i]);

    return ret;
}

extern u8
maid_test_pkcs1_v1_5(void)
{
    /* Comparison with OpenSSL */

    u8 ret = 7;

    char *public =
        "308201090282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7eb6e243"
        "66aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec33ef2a9"
        "9e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7fc463febf30"
        "299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c31941534257299"
        "d206911a4a8a6163e26f82737e126b3e682567e6627429e48104e25af999c8a8"
        "6e6e30f1399c8d7a608dc427de103644519914288594a69c495a86cf43b12e7f"
        "b0a002eb31d1f889b9ad451b45ee15e871204f48c9ecd35432b7c429bcdf6287"
        "c22b7b6aec4975b3b8d8207bd8d497abc01a4efb31f01a8cdb8a389d6ec3936e"
        "573dd34b25fe5a650203010001";
    char *private =
        "308204a10201000282010043b2dcfb0682d13422d8fa6ef324691aa55cc65b7e"
        "b6e24366aac85b7a2afaa2cead22550de99822b1f73964437f8c82daedac8ec3"
        "3ef2a99e2343012da30f6a71d16da5b88dec4c89ab4ab99bf8eabe6dee7fc463"
        "febf30299d2667d5a380fc94f6a5aa358fe4cfaf4a833b4e536c1f8c31941534"
        "257299d206911a4a8a6163e26f82737e126b3e682567e6627429e48104e25af9"
        "99c8a86e6e30f1399c8d7a608dc427de103644519914288594a69c495a86cf43"
        "b12e7fb0a002eb31d1f889b9ad451b45ee15e871204f48c9ecd35432b7c429bc"
        "df6287c22b7b6aec4975b3b8d8207bd8d497abc01a4efb31f01a8cdb8a389d6e"
        "c3936e573dd34b25fe5a6502030100010282010033bad2fcc5e6e430f087d825"
        "3b8990fe996920f0fd0c862c76a0fd64591fca50e998866973ae11604198e5b3"
        "e597eb287a5daec39011e39f14856147df35802c1838ad8e3a4dc8485bd215d1"
        "6a8b73e47b6009256a3b58a056cc0c72bf5ea6cb5a9075da6fff3a1a3099c159"
        "69ea78ee4a5400118bbd29aabc3fe454b0acb8e9a275387ba927bb4512001b51"
        "f8525b87b5b4dbddd5f90e2b8416b796b791387737bb140f89fb6739face7857"
        "5c0fb9175757a02411d033c32f6ab9a869a7d8eed90be34dcada047d5d93b232"
        "15ea34827c9b2749860ea7ae4a3fc1aa349505fd1cde16ab3caea5b2782fff75"
        "e77230fd5dbcfb9df777310b2778bfb52cb778810281805c9e59874192f39cf9"
        "77f915cb9df43c55d5ea4d740d39175ee5270745e39a20edc70c4f0cc81b31d6"
        "435bac25f97b6a726a5916d8923b3dd67ac50a00a87547bc7ccb446bd0f36480"
        "bff4c38c2bb2412cc556cf92426a53f2adba28cbfacd96e9d0c4f067466443e6"
        "b5913eab24d16b400b2ebbeedc37bf374b7eb81de2feb102818100bb1ef08afa"
        "0e0f59f5b0b54213f79cc181fe33d1ae5e802fcee5cd9d857774848fe9cc457d"
        "1cca5ddfae7d7e72671240b6a010c9b2839912f2c93068a4ce18b2fc3eb75be8"
        "317beaea4edf23437a77f708c7e7e789aa4d941f15d1520b3570f69b76745a08"
        "b7f96df9575eb1b471a8cf699c7f54740c536160e3e88ec17f0bf50281801565"
        "cc1f508a07d85b565968acab28730c0da8dd0e13c3fddf41a7dba94ce51df871"
        "4529ba353cfb2d9a50429c5f6020fea00d4716efe9d9e68464a363f5876af464"
        "0c7e193ea40cb32626014b9008d5bfe733a02f154305740aa8f8a5efa2b1dc01"
        "0c8ed1fd544acfb161060e7a2a1bd227033c0dfa38b2e7ae7c6f43105f710281"
        "81009cd53cc52efa33d1b1842f17b8069442f802284a793c4972489601752255"
        "51ba7da87686536b9b0d7d1a11a2b69e3f05304c0e660f120f6d7b423729addf"
        "f381a8bba4110b16d686b965ebcdf193a712cd3047e59f53b6fc0be5cc705866"
        "ad4c74569f048b442f7206473d5df220455dba65e9aece293a8566a0fedd0fbe"
        "bd350281802d6b6e6718bbd8ea3ed0a15c30d724282368b719121a4414b57282"
        "32ba628294cfb20c21ae5fa8c50b5e529617e97b2048eb637a31b76e1ae3db6d"
        "a6b02ed9b49c460809fa00bc9533483c7c962dc076a58ef56163550bf98d1ae2"
        "c76cd31542e79a71a6d593c1944eb1860a9a544514f2a451f08a9898b36aeb1a"
        "bf23747952";

    char *in[] =
        {"4e48c4228f01db757fda98686fa5aef95aec63cc",
         "89e22066badb9d5262fb51d981cd4e9b2ac5865d8c5238df9dbc1ad1",
         "dd101d8844273c7a5befef11512d673c0ac400fa34667c1c217c6b29c3732879",
         "576d7898741ac32308d74569e22fbce8fc85f4b814f7440de90b6d057268201f"
         "f77ed79741161d48dd33b8f2ad0886e2",
         "c3829c88ea2a4f8a21d48e929a75196516c906fa05cacb6cb8d2c254a2fa63de"
         "5b8b2bd4444480799bbbed199574e09b4a541cb548f01d3cb46a147f64446487",
         "e1bb41e7664ba644f50d6c6e5a2ea6a267ab471fd71fe3f54088c3d9",
         "7697b103b1f31832eec478e2d0f3b90a64d245182c8069d5d21ebf0c960aeb76"};
    char *out[] =
        {"3c55e44519d78b0d46c0db23ef74834199216fdba052cf3abfa2faea4f2c7180"
         "2c17e2ce7e7a601b2fad8c592cb9f318934d86a16472f5a499892b4c34530c92"
         "f6cb91b1ceaf4328aebd0acb403f2b18f8336a632cbc2f5b4588f6dc26ef9563"
         "c2fd7cd249f26aeb4307a082dd3e6ab686840ab9e94617d477909fe440006b82"
         "8a69b18e27c43eb64f52fdffc129e91978f3278e9e8a2abe91226e41b3f3205f"
         "7eccef90515b2e0c3f9c784207d3ffdbfadcf26217f9482ebd64f0e7deb3c0dd"
         "2ea63f33d6ec71db0eb251fdabe3f6f373f3a35348d509a11983d5cb9b902d89"
         "346f3365f90fc42023ed5ed0da42eebf6a2d2b57dce3548d0ce7187337f8b8fe",
         "2b65e24beb4a97605e6402c961d13d4d7d7d7e1b3154a8362188c6c7b7f1dafc"
         "c544e7728b448978a7e74340404fd78a0767951921bed34e49e4ddc2488ce423"
         "fbd0f5e3c0159848644f3cb94d398460cff6318895422d65460128fd1c8c7ded"
         "8ab77ff4ef4caf0689b1775ddac471e5a1eb95358769c70ba0e2f6154e8fc250"
         "c57cda4f05fa262291dbdf4cce267e2b23838f22898d490ec24f757be074d151"
         "83f7497e45480172c0bd78b2dc3a4c4b7547adf8a9a3691f28d508d1196d02fb"
         "cbf53c06df1ba01d036fbde8329a58edcc349801188446ebeeff2535b501680f"
         "2015bb202c734ad072093e07c3892c6353cf7eabf1f929d8e6be59e0ea56d041",
         "0777838b7db1ed1ff6cf76ed9d07fcb572907c698a09482db93f2302c77d53bf"
         "f6580a4795a33d49ce12989fc6b559edd34a09a0001a7adc2dcbdfa3b1c02266"
         "71295bb84cf82b46b63d7174d03f4c855ad0e92dc18bea095482d482f9c2cd9c"
         "6f4d0aedac2e8fff52bd1a6a1d786eb59ab0b51e3e9a8fa5358d32df7869fa63"
         "4ffbc754fcb8f2da0bb3dc8bf4e9dc80129743e29f4f4b9069dd5bdd47467719"
         "b462fea4b5cc1561200cb98b71b5a7a1b2008b37a563d5a0dafe509e85621bc0"
         "ad911b0bfbccff43c64b44c08a265a9af628f900a28ce97af881ed16682d238d"
         "c28b2af4b40d99649675865a989be5f5409226aed974fe295a0ff91db3de434a",
         "3d4923fbad7ff08d7844720bcec485e3ff18404803659817f2a9394f51f4eb59"
         "936401eb14b8caca307434c617f9bced6c6dba5e4bd0403c0768df6d8769f364"
         "587462ad6045887029dc7f4917b0fd56fc0a84aa02758b8f87f042cf18c89410"
         "0e8b2d1ceeba4505d5101455faa1102137f7eb5ea6fdfc47b7b61f9c9c9c76e6"
         "7f718aa9076045114e0cd28ff9a5ebe3ab15f6fd0a5e9149f14ef4a917a2a810"
         "11d9b72dc661b7365c6b588f5a9ce7f8f25893c2c65ef1fdbf6f45738af71083"
         "9701092e6a42c4c2e61ae1b2c5fc564a213834ccdfa1e8e46c69e590a0fec79e"
         "fc48367e7d70219f6a4d4edeb1f87470d49a81ab55c4432673bb08eb891cb5e3",
         "18809837a151abb49efe6b6eb9289c4e25d3ee5882632f404b65667e4a769ae2"
         "2b31f7309b8f0216d24bdab441cd18d61b24304508c2259bd37b387975f0dbb5"
         "3f041cdcbe80d727ef736b7a1354643cd486f5b23923a168bf9fa228d517deba"
         "c347acf3d785ef7144ff31cb425ec66e087a881690ff3859655f90d5bc5945ef"
         "365f6f760617b5a0cadf5e8f713548922dcd6f06427b39020205b268033d8092"
         "03625ed9ab42dafeaf5a04724dbdc8a98a7594e45d30bf195039800e27cfbf7c"
         "570935e987e348be2e597f6b56acfb7a9574022324503a8903d2739ef48c5a28"
         "197729297ab8277ca9370c8cb94d3683f14b97ba21f2f37ce821d12b01ddd10c",
         "37c101445c12de124cbce3729f09563220d6593f8ac3786d63da727de86c3004"
         "27c1af3f0548c40d01ae5f1a4bdaea5f5dd5d3b9f56a2641e6fb3b256708587a"
         "efdb6aae02538d33e9ef2b53c08c33559b33afd064e8b7982fedcf4bf34ccd6f"
         "e061817b400290468461bb9d292058ce82cdc41896caa9f54a2e27d309191556"
         "ef4188b58c8e9ab060db8caaebe0e32ff67c8db109e1e08d0c11d89ec22eed14"
         "3a0645baef3fcd80276f7b74e6dcab0f64a94de8b5d98f7c8ee3b3d38cea104e"
         "cfc224f504e80113ffac8350bd958c848a03795d3d680f2a0f007f242f71a058"
         "25fd44ab14a276c2255754cf985ed4e118e2ef64678a8df72ab53cc9804e2f55",
         "1b2be423e78681631cc23dc428d254dd8fefa5acbb773db1c08c16add6e32b6a"
         "c081a278a2fc92649f17c512fb95dd82a00d171c3a709690e4bf1585b4a54799"
         "3569ef6b92f5486af968a23a9892ab67e5989e7285ab5f16b2cdcde13173821c"
         "fb71f0d73affcefb254d790cf565b3328dbe7c66c25eea24878cc89a26021e91"
         "1ea8f757a1eb0e5514f7366004ff8a259c7d2a720e6339c7f7cc853007a19410"
         "c41dd0777e844af64a7c03edcab6150410578521fe1e81a50253ec6cff4386c4"
         "ae03e16cdd0a6135a7014b562e5ad3f21beee1cddc4237589ddc716a0925c8ec"
         "db9514049ef444c859b1891551b4974d81746606c55715bf4430647b2563e286"};

    struct maid_sign_def defs[] =
        {maid_pkcs1_v1_5_sha1,
         maid_pkcs1_v1_5_sha224,     maid_pkcs1_v1_5_sha256,
         maid_pkcs1_v1_5_sha384,     maid_pkcs1_v1_5_sha512,
         maid_pkcs1_v1_5_sha512_224, maid_pkcs1_v1_5_sha512_256};

    for (u8 i = 0; i < 7; i++)
        ret -= test_pkcs1_v1_5(defs[i], public, private, in[i], out[i]);

    return ret;
}

extern u8
maid_test_dh(void)
{
    /* KAS FFC NIST test vectors */

    u8 ret = 1;

    char *g[] =
        {"4a1af3a492e9ee746e57d58c2c5b41415ed45519dcd93291f7fdc257ff0314db"
         "f1b7600c43593fffacf1809a156fd86eb78518c8ec4e594ae291434ceb95b62e"
         "9aea536880646940f9ecbd8589269767afb0ad001bd4fd94d3e992b1b4bc5aaa"
         "9280893b39056c2226fe5a286c37505a3899cff3c19645dc01cb2087a5008cf5"
         "4dc2efb89bd187beedd50a291534594c3a052205444f9fc84712248ea879e467"
         "ba4d5b755695ebe88afa8e018c1b7463d92ff7d3448fa8f5af6c4fdbe7c96c71"
         "22a31df140b2e09ab672c9c01316a24ae192c75423ab9da1a1e50bedbae88437"
         "b2e7fe328dfa1c537797c7f348c9db2d75529d4251786268054515f8a24ef30b"};
    char *p[] =
        {"c57ca24f4bd68c3cdac7baaaea2e5c1e18b27b8c55659feae0a136532b36e04e"
         "3e64a9e4fc8f326297e4bef7c1de075a8928f3fe4ffe68bcfb0a7ca4b3144889"
         "9fafb843e2a0625cb4883f065011fe658d49d2f54b7479db06629289eddacb87"
         "3716d2a17ae8de92ee3e414a915eedf36c6b7efd159218fca7ac428557e9dcda"
         "55c98b289ec1c4464d88ed628edb3fb9d7c8e3cfb8342cd26f280641e3668cfc"
         "72ff263b6b6c6f73def29029e06132c412740952ecf31ba64598acf91c658e3a"
         "91844b238ab23cc9faeaf138ced805e0fa44681febd957b84a975b88c5f1bbb0"
         "49c3917cd313b947bb918fe52607aba9c5d03d954126929d1367f27e1188dc2d"};
    char *prv[] =
        {"0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "00000000d00ec7e80d5cc3405f9b40e0b52503c888273cef46a98d289a602a1a"};
    char *pub[] =
        {"7d0660bfce9e7263f6bfc79bca58feca7131077d31a964dd3a2a9a493420fb49"
         "62be61aefa37635354563671f66186e8096e6e888160ce1ddcf1b5fe4bf5c9f6"
         "c99a63015d1723adcd8a2aebd4847ab022896f8107114cbcf34ea32435d5a268"
         "9f7356d3894aeafd9ad80baab0fdd2671540a59b2fc789fd0be4154357df8d7f"
         "996f2076e963fa59d5ffd9fe8a006ce09c052ebebcc6db71b7778fb0d3030f18"
         "ad2604d3152a207f6625a63121bd0217a4424856d2167af8fea3e77d20ebe161"
         "24d0e74f95fb8b5ed619447152e4883d00fc2e3d14f26a724fde7e870f196ec5"
         "a040bbbaf4da12034e5cbf94624e2dc280b1d44457c8820d3c485a8023d6bb44"};
    char *pub2[] =
        {"78045869392d56f3520712a68f29466d8a89cf419192504c453c224dbc9a0ffd"
         "297d6cc1a370eee93981399da4c70897aab48f334f05a5562733e4e731c37f17"
         "3880760088edb1e9986a5d430806d5146424d93a7fa4a391659ff9666755e75a"
         "1438816113e1448e6e14b46ce8ad7908fec3b8e502257263eabafefc9a3b9c64"
         "522150fbc211f45eef4335fbc6dc01a9156943abae05c3b177ac9d7e3bd3c57e"
         "f58df9523bcfc5532d67ac61174f6c9c09a93892dfbf490d150b02f224385619"
         "cf6db90a6f79042ef9efdbbcdbf2a38b0112ec40dc6bff2bc7f596417840e3ac"
         "4aa5a5d044e71a876a10a204df713447f2920d92180e144318ce0e18b87eef6e"};
    char *secret[] =
        {"0df1d1b0faae8b8afb7c47884849f23a2d8f01ee47141e91d54949ff7fd0d110"
         "ac4cccc67f428a04ee6441f81d1a04263b99b5eef61794fd3d584bd7e1f4f610"
         "b8dcb78d045f721319f6a8333e828c56b1975c4fa3d31eeb61a4c2042cc9226c"
         "6eeea75b668bfbb50d1b7ca188c79585a44ce538041e941b03e6cca4365802be"
         "79895ad2601e47e62635153a91ef92a90f8958d3f7d2c503613778511e394d92"
         "8fddb07dc7adf434854e948519f1bfb7ca023bb0464596b6010e380da5d7135c"
         "5a0d41c56d3792f6dc5e09a42f7e2a9486d8590b01542ae69fa14fa582ca7344"
         "434705649d687885cc2477aa4c088d47339548926b9f7a17138267f3e45589db"};

    for (u8 i = 0; i < 1; i++)
        ret -= test_dh(2048, g[i], p[i], prv[i], pub[i], pub2[i], secret[i]);

    return ret;
}
