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

#include <maid/mp.h>
#include <maid/ecc.h>
#include <maid/kex.h>
#include <maid/mac.h>
#include <maid/mem.h>
#include <maid/rng.h>
#include <maid/aead.h>
#include <maid/hash.h>
#include <maid/sign.h>
#include <maid/stream.h>

#include <internal/mp.h>
#include <internal/types.h>

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

/*
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
test_mp_expmod(size_t words, char *a, char *b, char *m, char *r)
{
    bool ret = true;

    TEST_IMPORT_MP(words, am, ab, a)
    TEST_IMPORT_MP(words, bm, bb, b)
    TEST_IMPORT_MP(words, mm, mb, m)
    TEST_IMPORT_MP(words, rm, rb, r)

    size_t size = words * sizeof(maid_mp_word);
    if (ret)
    {
        maid_mp_expmod(words, am, bm, mm);
        ret &= maid_mem_cmp(am, rm, size);
    }

    return ret;
}
*/

static bool
test_stream(const struct maid_stream_def *def, char *key, char *nonce,
            u32 counter, char *input, char *output)
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
test_mac(const struct maid_mac_def *def, char *key, char *input, char *tag)
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
test_aead(const struct maid_aead_def *def, char *key, char *nonce,
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
test_hash(struct maid_hash_def *def, char *input, char *output)
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
test_rng(const struct maid_rng_def *def, char *entropy, char *output)
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
        maid_ecc *c = maid_ecc_new(&def);
        maid_ecc_point *r0 = maid_ecc_alloc(c);
        maid_ecc_point *r1 = maid_ecc_alloc(c);
        maid_ecc_point *r2 = maid_ecc_alloc(c);
        if (c && r0 && r1 && r2)
        {
            maid_ecc_base(c, r0);
            maid_ecc_copy(c, r1, NULL);
            maid_ecc_copy(c, r2, r0);

            u32 flags = maid_ecc_flags(c);

            ret = maid_ecc_encode(c, tb, r2);
            ret &= maid_mem_cmp(tb, bb, sizeof(tb));
            if (!(flags & MAID_ECC_NO_INF))
            {
                ret &= maid_ecc_encode(c, tb, r1);
                ret &= maid_mem_cmp(tb, ib, sizeof(tb));
            }
            else
                ret &= !maid_ecc_encode(c, tb, r1);
            ret &= maid_ecc_decode(c, bb, r1);
            ret &= maid_ecc_encode(c, tb, r1);
            ret &= maid_mem_cmp(tb, bb, sizeof(tb));

            if (ret && maid_ecc_decode(c, bb, r0))
            {
                maid_ecc_dbl(c, r0);
                ret = maid_ecc_encode(c, tb, r0) &&
                      maid_mem_cmp(tb, db, sizeof(tb));
            }

            if (ret && !(flags & MAID_ECC_DIFF_ADD) &&
                maid_ecc_decode(c, bb, r1))
            {
                maid_ecc_add(c, r0, r1);
                ret = maid_ecc_encode(c, tb, r0) &&
                      maid_mem_cmp(tb, rb, sizeof(tb));
            }

            if (ret && maid_ecc_decode(c, bb, r0))
            {
                maid_ecc_mul(c, r0, sm);
                ret = maid_ecc_encode(c, tb, r0) &&
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
    u8 ret = 14;

    size_t words = MAID_MP_WORDS(256);

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
    ret -= test_mp_a(words, maid_mp_mul, sa, sb, false,
           "0c38d648e0ed7643ad6b5926892d84e50348a8372c6ee86aecbc259473fecd96");

    ret -= test_mp_s(words, maid_mp_shl, sa, 33, true,
           "002363a195fd757c1bc3e3da2363a1bd81a3e3dbbd5b7d4f95fd7cf400000000");
    ret -= test_mp_s(words, maid_mp_shr, sa, 45, true,
           "000000000006068f8f68008d8e8657f5d5f06f0f8f688d8e86f6068f8f6ef56d");
    ret -= test_mp_s(words, maid_mp_sal, sa, 33, true,
           "002363a195fd757c1bc3e3da2363a1bd81a3e3dbbd5b7d4f95fd7cf400000000");
    ret -= test_mp_s(words, maid_mp_sar, sb, 45, false,
           "fffffffffffef56e06f6f56fd675f77dd5f05d6e57f05f52bfd656f6801f688d");

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
        ret -= test_stream(&maid_chacha20, keys[i], nonces[i], counters[i],
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
        ret -= test_mac(&maid_poly1305, keys[i], datas[i], tags[i]);

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
        ret -= test_aead(&maid_chacha20poly1305, keys[i], nonces[i],
                         ads[i], inputs[i], outputs[i], tags[i], modes[i]);

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
        ret -= test_hash(&defs256[i], input0, outputs0[i]);
        ret -= test_hash(&defs256[i], input1, outputs1[i]);
    }

    struct maid_hash_def defs512[] = {maid_sha384,     maid_sha512,
                                      maid_sha512_224, maid_sha512_256};

    for (u8 i = 0; i < 4; i++)
    {
        ret -= test_hash(&defs512[i], input0, outputs0[i + 2]);
        ret -= test_hash(&defs512[i], input2, outputs2[i + 0]);
    }

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

    ret -= test_mac(&maid_hmac_sha224,     keys[0], data, tags[0]);
    ret -= test_mac(&maid_hmac_sha256,     keys[0], data, tags[1]);
    ret -= test_mac(&maid_hmac_sha384,     keys[1], data, tags[2]);
    ret -= test_mac(&maid_hmac_sha512,     keys[1], data, tags[3]);
    ret -= test_mac(&maid_hmac_sha512_224, keys[1], data, tags[4]);
    ret -= test_mac(&maid_hmac_sha512_256, keys[1], data, tags[5]);

    return ret;
}

extern u8
maid_test_curve25519(void)
{
    return 1 - test_ecc(maid_curve25519, MAID_MP_WORDS(256),
                        "09000000000000000000000000000000"
                        "00000000000000000000000000000000",
                        "00000000000000000000000000000000"
                        "00000000000000000000000000000000",
                        "fb4e68dd9c46ae5c5c0b351eed5c3f8f"
                        "1471157d680c75d9b7f17318d542d320",
                        "123c71fbaf030ac059081c62674e82f8"
                        "64ba1bc2914d5345e6ab576d1abc121c",
                        "00000000000000000000000000000000"
                        "000000000000000000000000cafebabe",
                        "9621848b67243ccc97468fa237c8ff4c"
                        "675c04824a59a4b4607037f6116be166");
}

extern u8
maid_test_edwards25519(void)
{
    return 1 - test_ecc(maid_edwards25519, MAID_MP_WORDS(256),
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
