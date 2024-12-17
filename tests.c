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

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>
#include <maid/rng.h>
#include <maid/hash.h>

#include <maid/pub.h>
#include <maid/sign.h>
#include <maid/kex.h>

#include <maid/import.h>

/* Helper functions */

static u8
hex_digit(char c)
{
    u8 ret = 0;

    if (c >= '0' && c <= '9')
        ret = c - '0';
    else if (c >= 'a' && c <= 'f')
        ret = 10 + (c - 'a');
    else if (c >= 'A' && c <= 'F')
        ret = 10 + (c - 'A');

    return ret;
}

static size_t
hex_read(u8 *data, char *hex)
{
    size_t ret = 0;

    if (hex)
    {
        /* Using very low pointer values as zeros */
        if ((u64)hex < 1024)
        {
            ret = (size_t)hex;
            memset(data, '\0', ret);
        }
        else
        {
            ret = strlen(hex) / 2;
            for (size_t i = 0; i < ret; i++)
            {
                data[i] = (hex_digit(hex[(i * 2) + 0]) << 4) |
                          (hex_digit(hex[(i * 2) + 1]) << 0) ;
            }
        }
    }

    return ret;
}

/* Memory utilities */

static u8
mem_tests(void)
{
    u8 ret = 64;

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

    memset(zeros, '\0', sizeof(zeros));
    for (size_t i = 0; i < 7; i++)
    {
        char buf[16] = {0};
        size_t l  = strlen(base64[i]);
        size_t l2 = strlen(ascii[i]);

        ret -= maid_mem_import(buf, sizeof(buf), base64[i], l) == l;
        ret -= memcmp(buf, ascii[i], l2) == 0;
        ret -= memcmp(&(buf[l2]), zeros, sizeof(buf) - l2) == 0;
    }

    for (size_t i = 0; i < 1; i++)
    {
        char buf[16] = {0};
        size_t l = strlen(base64[3]);
        size_t l2 = strlen(ascii[3]);

        ret -= maid_mem_import(buf, sizeof(buf), base64[6], l) == l;
        ret -= memcmp(buf, ascii[3], l) == 0;
        ret -= memcmp(&(buf[l2]), zeros, sizeof(buf) - l2) == 0;
    }

    for (size_t i = 0; i < 7; i++)
    {
        char buf[16] = {0};
        size_t l  = strlen(ascii[i]);
        size_t l2 = strlen(base64[i]);

        ret -= maid_mem_export(ascii[i], l, buf, sizeof(buf)) == l2;
        ret -= memcmp(buf, base64[i], l2) == 0;
        ret -= memcmp(&(buf[l2]), zeros, sizeof(buf) - l2) == 0;
    }

    for (size_t i = 0; i < 1; i++)
    {
        char buf[16] = {0};
        size_t l  = strlen(ascii[6]);
        size_t l2 = 5;
        size_t l2m4 = l2 % 4;

        ret -= maid_mem_export(ascii[6], l, buf, l2) == l2 - l2m4;
        ret -= memcmp(buf, base64[3], l2m4) == 0;
        ret -= memcmp(&(buf[l2 - l2m4]), zeros, sizeof(buf) - l2 + l2m4) == 0;
    }

    char *bad64[] = {"Zm9vYg", "Zm9vY%", "Zm9vY=Fy", "Zm9vYm=y"};
    for (size_t i = 0; i < 4; i++)
    {
        char buf[16] = {0};
        size_t l  = strlen(bad64[i]);

        ret -= maid_mem_import(buf, sizeof(buf), bad64[i], l) == 0;
        ret -= memcmp(buf, zeros, sizeof(buf)) == 0;
    }

    return ret;
}

/* Multiprecision utilities */

static void
mp_test(size_t words, u8 *val, maid_mp_word *a, maid_mp_word *b,
        maid_mp_word *c, maid_mp_word *d,
        size_t ia, size_t ib, size_t ic, size_t id)
{
    size_t size = sizeof(maid_mp_word) * words;

    for (u8 i = 0; i < words; i++)
    {
        maid_mp_read(words, a, &(val[ia * size]), true);
        maid_mp_read(words, b, &(val[ib * size]), true);
        maid_mp_read(words, c, &(val[ic * size]), true);
        maid_mp_read(words, d, &(val[id * size]), true);
    }
}

static void
tmp_clean(size_t words, maid_mp_word *tmp, size_t total)
{
    for (size_t i = 0; i < words * total; i++)
        tmp[i] = i;
}

static bool
tmp_check(size_t words, maid_mp_word *tmp, size_t used, size_t total)
{
    bool ret = true;

    for (size_t i = words * used; i < words * total; i++)
    {
        if (tmp[i] != i)
            ret = false;
    }
    tmp_clean(words, tmp, total);

    return ret;
}

static u8
mp_tests(void)
{
    u8 ret = 64;

    size_t words = maid_mp_words(128);
    ret -= (sizeof(maid_mp_word) == 4) ? (words == 4) : (words == 2);

    u8 val[] = {
    /* a */            0xc0, 0xd1, 0xf1, 0xed, 0x00, 0x11, 0xb1, 0xd0,
                       0xca, 0xfe, 0xba, 0xbe, 0x0d, 0xe1, 0xf1, 0xed,
    /* b */            0x11, 0xb1, 0xd0, 0xde, 0xc0, 0xd1, 0xf1, 0xed,
                       0xde, 0xad, 0xbe, 0xa7, 0xca, 0xfe, 0xbe, 0x7a,
    /* c = a(le) */    0xed, 0xf1, 0xe1, 0x0d, 0xbe, 0xba, 0xfe, 0xca,
                       0xd0, 0xb1, 0x11, 0x00, 0xed, 0xf1, 0xd1, 0xc0,
    /* !a */           0x3f, 0x2e, 0x0e, 0x12, 0xff, 0xee, 0x4e, 0x2f,
                       0x35, 0x01, 0x45, 0x41, 0xf2, 0x1e, 0x0e, 0x12,
    /* a & b */        0x00, 0x91, 0xd0, 0xcc, 0x00, 0x11, 0xb1, 0xc0,
                       0xca, 0xac, 0xba, 0xa6, 0x08, 0xe0, 0xb0, 0x68,
    /* a | b */        0xd1, 0xf1, 0xf1, 0xff, 0xc0, 0xd1, 0xf1, 0xfd,
                       0xde, 0xff, 0xbe, 0xbf, 0xcf, 0xff, 0xff, 0xff,
    /* a ^ b */        0xd1, 0x60, 0x21, 0x33, 0xc0, 0xc0, 0x40, 0x3d,
                       0x14, 0x53, 0x04, 0x19, 0xc7, 0x1f, 0x4f, 0x97,
    /* a + b */        0xd2, 0x83, 0xc2, 0xcb, 0xc0, 0xe3, 0xa3, 0xbe,
                       0xa9, 0xac, 0x79, 0x65, 0xd8, 0xe0, 0xb0, 0x67,
    /* a - b */        0xaf, 0x20, 0x21, 0x0e, 0x3f, 0x3f, 0xbf, 0xe2,
                       0xec, 0x50, 0xfc, 0x16, 0x42, 0xe3, 0x33, 0x73,
    /* a << 33 */      0x00, 0x23, 0x63, 0xa1, 0x95, 0xfd, 0x75, 0x7c,
                       0x1b, 0xc3, 0xe3, 0xda, 0x00, 0x00, 0x00, 0x00,
    /* a >> 45 */      0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x8f,
                       0x8f, 0x68, 0x00, 0x8d, 0x8e, 0x86, 0x57, 0xf5,
    /* a <<< 33 */     0x00, 0x23, 0x63, 0xa1, 0x95, 0xfd, 0x75, 0x7c,
                       0x1b, 0xc3, 0xe3, 0xda, 0x00, 0x00, 0x00, 0x00,
    /* a >>> 45 */     0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x06, 0x8f,
                       0x8f, 0x68, 0x00, 0x8d, 0x8e, 0x86, 0x57, 0xf5,
    /* a * b */        0x84, 0x05, 0x36, 0x41, 0xa6, 0x66, 0x63, 0x6e,
                       0xce, 0x9f, 0xd3, 0x8e, 0x5a, 0x61, 0x30, 0xf2,
    /* a / b */        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    /* a % b */        0x0f, 0xdf, 0xc9, 0x39, 0x77, 0xde, 0x3e, 0x86,
                       0x18, 0x35, 0x48, 0x30, 0x1f, 0xee, 0x81, 0x29,
    /* a ^ b */        0x7c, 0x2f, 0x55, 0x6f, 0x88, 0xbe, 0x1b, 0x8e,
                       0x49, 0x05, 0xc9, 0x0b, 0x4b, 0x83, 0x83, 0x49,
    /* (a * b) % c */  0x86, 0x1b, 0xa5, 0x38, 0x59, 0x6f, 0xc4, 0x9e,
                       0xd3, 0x5b, 0x9d, 0x91, 0x53, 0x54, 0x79, 0x32,
    /* (a ^ b) % c */  0x80, 0x12, 0xde, 0x12, 0x3b, 0x22, 0x46, 0x5f,
                       0xf9, 0xf1, 0x93, 0x51, 0xc2, 0x4c, 0x90, 0xc9,
    /* (a ^ -1) % b */ 0x0d, 0x9e, 0xbe, 0x15, 0xeb, 0x7f, 0xd5, 0x8e,
                       0x40, 0xef, 0xba, 0x9a, 0xe0, 0x11, 0xa3, 0xcb,
    /* (b ^ c) % a */  0x71, 0x57, 0xe9, 0xfb, 0xb7, 0x15, 0x7f, 0x01,
                       0xeb, 0x11, 0x23, 0x7a, 0xac, 0x1c, 0x17, 0x42};

    size_t size = sizeof(maid_mp_word) * words;

    maid_mp_word z[words];
    maid_mp_word f[words];
    memset(z, 0x00, size);
    memset(f, 0xff, size);

    maid_mp_word a[words];
    maid_mp_word b[words];
    maid_mp_word c[words];
    maid_mp_word d[words];

    size_t tmp_l = 64;
    maid_mp_word tmp[words * tmp_l];
    tmp_clean(words, tmp, tmp_l);

    /* read/write */
    mp_test(words, val, a, b, c, d, 0, 1, 2, 0);
    maid_mp_write(words, a, &(val[2 * 16]), false);
    maid_mp_read(words, a, &(val[2 * 16]), true);
    ret -= memcmp(a, c, size) == 0;

    mp_test(words, val, a, b, c, d, 0, 3, 0, 0);
    maid_mp_not(words, a);
    ret -= memcmp(a, b, size) == 0;

    #define MAID_MP_TEST_A(id, r, zn) \
    mp_test(words, val, a, b, c, d, 0, 1, r, 0); \
    maid_mp_##id(words, a, b); \
    ret -= memcmp(a, c, size) == 0; \
    maid_mp_##id(words, a, NULL); \
    ret -= memcmp(a, (zn) ? z : c, size) == 0;

    MAID_MP_TEST_A(and, 4, false);
    MAID_MP_TEST_A(orr, 5, false);
    MAID_MP_TEST_A(xor, 6, false);

    /* cmp */
    mp_test(words, val, a, b, c, d, 0, 1, 0, 0);
    ret -= maid_mp_cmp(words, a, b)    == -1;
    ret -= maid_mp_cmp(words, b, a)    ==  1;
    ret -= maid_mp_cmp(words, a, a)    ==  0;
    ret -= maid_mp_cmp(words, a, NULL) == -1;

    MAID_MP_TEST_A(mov, 1, true);
    MAID_MP_TEST_A(add, 7, false);
    MAID_MP_TEST_A(sub, 8, false);

    #define MAID_MP_TEST_S(id, s, r, zn) \
    mp_test(words, val, a, b, c, d, 0, 0, r, 0); \
    maid_mp_##id(words, a, s); \
    ret -= memcmp(a, c, size) == 0; \
    maid_mp_##id(words, a, 128); \
    ret -= memcmp(a, (zn) ? z : f, size) == 0;

    MAID_MP_TEST_S(shl, 33, 9,  true)
    MAID_MP_TEST_S(shr, 45, 10, true)
    MAID_MP_TEST_S(sal, 33, 11, true)
    MAID_MP_TEST_S(sar, 45, 12, false)

    #define MAID_MP_TEST_T(id, r, zn, mem) \
    mp_test(words, val, a, b, c, d, 0, 1, r, 0); \
    maid_mp_##id(words, a, b, tmp); \
    ret -= memcmp(a, c, size) == 0; \
    maid_mp_##id(words, a, NULL, tmp); \
    ret -= memcmp(a, (zn) ? z : c, size) == 0; \
    ret -= tmp_check(words, tmp, mem, tmp_l);

    MAID_MP_TEST_T(mul, 13, false, 1);
    MAID_MP_TEST_T(div, 14, false, 2);
    MAID_MP_TEST_T(mod, 15, true , 3);
    MAID_MP_TEST_T(exp, 16, false, 3);

    /* div2 */
    mp_test(words, val, a, b, c, d, 0, 1, 14, 0);
    maid_mp_div2(words, a, d, b, tmp);
    ret -= memcmp(a, c, size) == 0;
    maid_mp_div2(words, a, d, NULL, tmp);
    ret -= memcmp(a, c, size) == 0;
    mp_test(words, val, a, b, c, d, 0, 1, 15, 0);
    maid_mp_div2(words, a, d, b, tmp);
    ret -= memcmp(d, c, size) == 0;
    maid_mp_div2(words, a, d, NULL, tmp);
    ret -= memcmp(d, z, size) == 0;
    ret -= tmp_check(words, tmp, 3, tmp_l);

    #define MAID_MP_TEST_M(id, aa, bb, cc, r, mem, ...) \
    mp_test(words, val, a, b, c, d, aa, bb, cc, r); \
    maid_mp_##id(words, a, b, c, tmp,##__VA_ARGS__); \
    ret -= memcmp(a, d, size) == 0; \
    maid_mp_##id(words, a, NULL, c, tmp,##__VA_ARGS__); \
    ret -= memcmp(a, d, size) == 0; \
    ret -= tmp_check(words, tmp, mem, tmp_l);

    MAID_MP_TEST_M(mulmod, 0, 1, 2, 17, 12);
    MAID_MP_TEST_M(expmod, 0, 1, 2, 18, 14, false);
    MAID_MP_TEST_M(expmod, 0, 1, 2, 18, 14, true);

    /* invmod */
    mp_test(words, val, a, b, c, d, 0, 2, 0, 0);
    ret -= !maid_mp_invmod(words, a, b, tmp);
    ret -= memcmp(a, d, size) == 0;
    mp_test(words, val, a, b, c, d, 0, 1, 0, 19);
    ret -= maid_mp_invmod(words, a, b, tmp);
    ret -= memcmp(a, d, size) == 0;
    ret -= tmp_check(words, tmp, 21, tmp_l);

    MAID_MP_TEST_M(expmod2, 1, 2, 0, 20, 49, false);
    MAID_MP_TEST_M(expmod2, 1, 2, 0, 20, 49, true);

    return ret;
}

/* AES NIST SP 800-38A vectors */

static u8
aes_test(maid_block *bl, char *key_h,
         char *input_h, char *output_h, bool decrypt)
{
    u8 ret = 0;

    if (bl)
    {
        u8    key[32] = {0};
        u8  input[16] = {0};
        u8 output[16] = {0};

        hex_read(key,    key_h);
        hex_read(input,  input_h);
        hex_read(output, output_h);

        maid_block_renew(bl, key, NULL);
        maid_block_ecb(bl, input, decrypt);
        if (memcmp(input, output, sizeof(output)) == 0)
            ret = 1;
    }

    return ret;
}

static u8
aes_tests(void)
{
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

    u8 zeros[32] = {0};
    maid_block *aes128 = maid_block_new(maid_aes_128, zeros, zeros);
    maid_block *aes192 = maid_block_new(maid_aes_192, zeros, zeros);
    maid_block *aes256 = maid_block_new(maid_aes_256, zeros, zeros);

    for (u8 i = 0; i < 4; i++)
    {
        ret -= aes_test(aes128, key128, block[i], cipher128[i], false);
        ret -= aes_test(aes128, key128, cipher128[i], block[i], true);

        ret -= aes_test(aes192, key192, block[i], cipher192[i], false);
        ret -= aes_test(aes192, key192, cipher192[i], block[i], true);

        ret -= aes_test(aes256, key256, block[i], cipher256[i], false);
        ret -= aes_test(aes256, key256, cipher256[i], block[i], true);
    }

    maid_block_del(aes128);
    maid_block_del(aes192);
    maid_block_del(aes256);

    return ret;
}

/* AES-CTR NIST SP 800-38A vectors */

static u8
aes_ctr_test(maid_block *bl, char *key_h, char *iv_h,
             char *input_h, char *output_h)
{
    u8 ret = 0;

    if (bl)
    {
        u8    key[32] = {0};
        u8     iv[16] = {0};
        u8  input[64] = {0};
        u8 output[64] = {0};

        hex_read(key,   key_h);
        hex_read(iv,    iv_h);
        hex_read(input, input_h);

        size_t length = hex_read(output, output_h);

        maid_block_renew(bl, key, iv);
        maid_block_ctr(bl, input, length);
        if (memcmp(input, output, length) == 0)
            ret = 1;
    }

    return ret;
}

static u8
aes_ctr_tests(void)
{
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

    u8 zeros[32] = {0};
    maid_block *aes128 = maid_block_new(maid_aes_128, zeros, zeros);
    maid_block *aes192 = maid_block_new(maid_aes_192, zeros, zeros);
    maid_block *aes256 = maid_block_new(maid_aes_256, zeros, zeros);

    ret -= aes_ctr_test(aes128, key128, iv, block, cipher128);
    ret -= aes_ctr_test(aes128, key128, iv, cipher128, block);

    ret -= aes_ctr_test(aes192, key192, iv, block, cipher192);
    ret -= aes_ctr_test(aes192, key192, iv, cipher192, block);

    ret -= aes_ctr_test(aes256, key256, iv, block, cipher256);
    ret -= aes_ctr_test(aes256, key256, iv, cipher256, block);

    maid_block_del(aes128);
    maid_block_del(aes192);
    maid_block_del(aes256);

    return ret;
}

/* AES-GCM GCM Spec vectors */

static u8
aes_gcm_test(maid_aead *ae, char *key_h, char *nonce_h, char *ad_h,
             char *input_h, char *output_h, char *tag_h)
{
    u8 ret = 0;

    if (ae)
    {
        u8    key[32] = {0};
        u8  nonce[64] = {0};
        u8     ad[32] = {0};
        u8  input[64] = {0};
        u8 output[64] = {0};
        u8    tag[16] = {0};

        hex_read(key,   key_h);
        hex_read(nonce, nonce_h);
        hex_read(input, input_h);
        hex_read(tag,   tag_h);

        size_t length  = hex_read(output, output_h);
        size_t length2 = hex_read(ad,     ad_h);

        maid_aead_renew(ae, key, nonce);
        maid_aead_update(ae, ad, length2);
        maid_aead_crypt(ae, input, length, false);

        u8 tag2[16] = {0};
        maid_aead_digest(ae, tag2);

        if (memcmp(input, output, length)  == 0 &&
            memcmp(tag2, tag, sizeof(tag)) == 0 )
            ret = 1;
    }

    return ret;
}

static u8
aes_gcm_tests(void)
{
    u8 ret = 12;

    char  *key_z = (char *)32;
    char   key[] = "feffe9928665731c6d6a8f9467308308"
                   "feffe9928665731c6d6a8f9467308308";

    char   *iv_z = (char *)12;
    char iv_96[] = "cafebabefacedbaddecaf888";

    char     ad[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

    char  *data_z = (char *)16;
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

    u8 zeros[32] = {0};
    maid_aead *aes128 = maid_aead_new(maid_aes_gcm_128, zeros, zeros);
    maid_aead *aes192 = maid_aead_new(maid_aes_gcm_192, zeros, zeros);
    maid_aead *aes256 = maid_aead_new(maid_aes_gcm_256, zeros, zeros);
    maid_aead *aeads[] = {aes128, aes192, aes256};

    for (u8 i = 0; i < 3; i++)
    {
        ret -= aes_gcm_test(aeads[i], key_z, iv_z,  "", "",
                            "",            tags[i][0]);
        ret -= aes_gcm_test(aeads[i], key_z, iv_z,  "", data_z,
                            ciphers[i][0], tags[i][1]);
        ret -= aes_gcm_test(aeads[i], key,   iv_96, "", data,
                            ciphers[i][1], tags[i][2]),
        ret -= aes_gcm_test(aeads[i], key,   iv_96, ad, data_s,
                            ciphers[i][2], tags[i][3]);
    }

    maid_aead_del(aes128);
    maid_aead_del(aes192);
    maid_aead_del(aes256);

    return ret;
}

/* Chacha20 RFC8439 vectors */

static u8
chacha_test(maid_stream *st, char *key_h, char *nonce_h,
            u32 counter, char *input_h, char *output_h)
{
    u8 ret = 0;

    if (st)
    {
        u8      key[32] = {0};
        u8    nonce[16] = {0};
        u8  input[1024] = {0};
        u8 output[1024] = {0};

        hex_read(key,   key_h);
        hex_read(nonce, nonce_h);
        hex_read(input, input_h);

        size_t length = hex_read(output, output_h);

        maid_stream_renew(st, key, nonce, counter);
        maid_stream_xor(st, input, length);
        if (memcmp(input, output, length) == 0)
            ret = 1;
    }

    return ret;
}

static u8
chacha_tests(void)
{
    u8 ret = 11;

    char  *key_z = (char *)32;
    char key_1[] = "00000000000000000000000000000000"
                   "00000000000000000000000000000001";
    char key_f[] = "00ff0000000000000000000000000000"
                   "00000000000000000000000000000000";
    char key_s[] = "000102030405060708090a0b0c0d0e0f"
                   "101112131415161718191a1b1c1d1e1f";
    char key_r[] = "1c9240a5eb55d38af333888604f6b5f0"
                   "473917c1402b80099dca5cbc207075c0";

    char  *nonce_z = (char *)12;
    char nonce_2[] = "000000000000000000000002";
    char nonce_a[] = "000000000000004a00000000";

    char  *data_zs = (char *)32;
    char  *data_zb = (char *)64;
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

    u8 zeros[32] = {0};
    maid_stream *st = maid_stream_new(maid_chacha20, zeros, zeros, 0);
    for (u8 i = 0; i < 11; i++)
        ret -= chacha_test(st, keys[i], nonces[i], counters[i],
                           datas[i], ciphers[i]);
    maid_stream_del(st);

    return ret;
}

/* Poly1305 RFC8439 vectors */

static u8
poly1305_test(maid_mac *m, char *key_h, char *input_h, char *tag_h)
{
    u8 ret = 0;

    if (m)
    {
        u8     key[32] = {0};
        u8 input[1024] = {0};
        u8     tag[16] = {0};

        hex_read(key, key_h);
        hex_read(tag, tag_h);

        size_t length = hex_read(input, input_h);

        maid_mac_renew(m, key);
        maid_mac_update(m, input, length);

        u8 tag2[16] = {0};
        maid_mac_digest(m, tag2);

        if (memcmp(tag2, tag, sizeof(tag)) == 0)
            ret = 1;
    }

    return ret;
}

static u8
poly1305_tests(void)
{
    u8 ret = 11;

    char *keys[] = {(char *)32,
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

    char *datas[] = {(char *)128,
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

    char *tags[] = {(char *)16,
                    "36e5f6b5c5e06070f0efca96227a863e",
                    "f3477e7cd95417af89a6b8794c310cf0",
                    "4541669a7eaaee61e708dc7cbcc5eb62",
                    "03000000000000000000000000000000",
                    "03000000000000000000000000000000",
                    "05000000000000000000000000000000",
                    (char *)16,
                    "faffffffffffffffffffffffffffffff",
                    "14000000000000005500000000000000",
                    "13000000000000000000000000000000"};

    u8 zeros[32] = {0};
    maid_mac *m = maid_mac_new(maid_poly1305, zeros);

    for (u8 i = 0; i < 11; i++)
        ret -= poly1305_test(m, keys[i], datas[i], tags[i]);

    maid_mac_del(m);

    return ret;
}

/* Chacha20Poly1305 RFC8439 vectors */

static u8
chacha20poly1305_test(maid_aead *ae, char *key_h, char *nonce_h,
                      char *ad_h, char *input_h, char *output_h,
                      char *tag_h, bool decrypt)
{
    u8 ret = 0;

    if (ae)
    {
        u8      key[32] = {0};
        u8    nonce[12] = {0};
        u8       ad[16] = {0};
        u8  input[1024] = {0};
        u8 output[1024] = {0};
        u8      tag[16] = {0};

        hex_read(key,    key_h);
        hex_read(nonce,  nonce_h);
        hex_read(output, output_h);
        hex_read(tag,    tag_h);

        size_t length  = hex_read(input, input_h);
        size_t length2 = hex_read(ad,    ad_h);

        maid_aead_renew(ae, key, nonce);
        maid_aead_update(ae, ad, length2);
        maid_aead_crypt(ae, input, length, decrypt);

        u8 tag2[16] = {0};
        maid_aead_digest(ae, tag2);

        if (memcmp(input, output, length)   == 0 &&
            memcmp(tag2, tag, sizeof(tag)) == 0 )
            ret = 1;
    }

    return ret;
}

static u8
chacha20poly1305_tests(void)
{
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

    u8 zeros[32] = {0};
    maid_aead *ae = maid_aead_new(maid_chacha20poly1305, zeros, zeros);

    for (u8 i = 0; i < 2; i++)
        ret -= chacha20poly1305_test(ae, keys[i], nonces[i], ads[i],
                                     inputs[i], outputs[i], tags[i], modes[i]);

    maid_aead_del(ae);

    return ret;
}

/* CTR-DRBG NIST CAVP vectors */

static u8
ctr_drbg_test(maid_rng *g, char *entropy_h, char *output_h)
{
    u8 ret = 0;

    if (g)
    {
        u8 entropy[48] = {0};
        u8 output[128] = {0};

        hex_read(entropy, entropy_h);
        hex_read(output,  output_h);

        u8 input[128] = {0};
        maid_rng_renew(g, entropy);
        maid_rng_generate(g, input, sizeof(input));

        if (memcmp(input, output, sizeof(output)) == 0)
            ret = 1;
    }

    return ret;
}

static u8
ctr_drbg_tests(void)
{
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

    u8 zeros[48] = {0};
    maid_rng *aes128 = maid_rng_new(maid_ctr_drbg_aes_128, zeros);
    maid_rng *aes192 = maid_rng_new(maid_ctr_drbg_aes_192, zeros);
    maid_rng *aes256 = maid_rng_new(maid_ctr_drbg_aes_256, zeros);

    for (u8 i = 0; i < 3; i++)
    {
        ret -= ctr_drbg_test(aes128, entropy128[i], output128[i]);
        ret -= ctr_drbg_test(aes192, entropy192[i], output192[i]);
        ret -= ctr_drbg_test(aes256, entropy256[i], output256[i]);
    }

    maid_rng_del(aes128);
    maid_rng_del(aes192);
    maid_rng_del(aes256);

    return ret;
}

/* SHA-2 NIST CSRC examples */

static u8
sha2_test(maid_hash *h, char *input, char *output_h)
{
    u8 ret = 0;

    if (h)
    {
        u8 output[128] = {0};

        size_t length  = strlen(input);
        size_t length2 = hex_read(output, output_h);

        u8 output2[128] = {0};
        maid_hash_renew(h);
        maid_hash_update(h, (u8*)input, length);
        maid_hash_digest(h, output2);

        if (memcmp(output, output2, length2) == 0)
            ret = 1;
    }

    return ret;
}

static u8
sha2_tests(void)
{
    u8 ret = 12;

    maid_hash *sha224     = maid_hash_new(maid_sha224);
    maid_hash *sha256     = maid_hash_new(maid_sha256);
    maid_hash *sha384     = maid_hash_new(maid_sha384);
    maid_hash *sha512     = maid_hash_new(maid_sha512);
    maid_hash *sha512_224 = maid_hash_new(maid_sha512_224);
    maid_hash *sha512_256 = maid_hash_new(maid_sha512_256);

    char *input0 = "abc";
    char *input1 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char *input2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                   "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

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

    maid_hash *hashes256[] = {sha224, sha256};
    for (u8 i = 0; i < 2; i++)
    {
        ret -= sha2_test(hashes256[i], input0, outputs0[i]);
        ret -= sha2_test(hashes256[i], input1, outputs1[i]);
    }

    maid_hash *hashes512[] = {sha384, sha512, sha512_224, sha512_256};
    for (u8 i = 0; i < 4; i++)
    {
        ret -= sha2_test(hashes512[i], input0, outputs0[i + 2]);
        ret -= sha2_test(hashes512[i], input2, outputs2[i + 0]);
    }

    maid_hash_del(sha224);
    maid_hash_del(sha256);
    maid_hash_del(sha384);
    maid_hash_del(sha512);
    maid_hash_del(sha512_224);
    maid_hash_del(sha512_256);

    return ret;
}

/* HMAC RFC4231 test vectors + comparison with other implementations */

static u8
hmac_test(maid_mac *m, char *key_h, char *input_h, char *tag_h)
{
    u8 ret = 0;

    if (m)
    {
        u8    key[128] = {0};
        u8 input[1024] = {0};
        u8     tag[64] = {0};

        hex_read(key, key_h);
        hex_read(tag, tag_h);

        size_t length  = hex_read(input, input_h);
        size_t length2 = hex_read(tag,   tag_h);

        maid_mac_renew(m, key);
        maid_mac_update(m, input, length);

        u8 tag2[64] = {0};
        maid_mac_digest(m, tag2);

        if (memcmp(tag2, tag, length2) == 0)
            ret = 1;
    }

    return ret;
}

static u8
hmac_tests(void)
{
    u8 ret = 6;

    char *key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    char *data = "4869205468657265";

    char *tags[] = {"896fb1128abbdf196832107cd49df33f"
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

    u8 zeros[128] = {0};
    maid_mac *macs[] = {maid_mac_new(maid_hmac_sha224,     zeros),
                        maid_mac_new(maid_hmac_sha256,     zeros),
                        maid_mac_new(maid_hmac_sha384,     zeros),
                        maid_mac_new(maid_hmac_sha512,     zeros),
                        maid_mac_new(maid_hmac_sha512_224, zeros),
                        maid_mac_new(maid_hmac_sha512_256, zeros)};

    for (u8 i = 0; i < 6; i++)
        ret -= hmac_test(macs[i], key, data, tags[i]);

    for (u8 i = 0; i < 6; i++)
        maid_mac_del(macs[i]);

    return ret;
}


/* RSA Primitives NIST test vectors */

static u8
rsa_test(maid_pub *pub, maid_pub *prv, char *e_h, char *d_h, char *N_h,
         char *input_h, char *output_h)
{
    u8 ret = 0;

    if (pub && prv)
    {
        u8 e8    [128] = {0};
        u8 d8    [128] = {0};
        u8 N8    [128] = {0};
        u8 input [128] = {0};
        u8 output[128] = {0};

        hex_read(e8,     e_h);
        hex_read(d8,     d_h);
        hex_read(N8,     N_h);
        hex_read(input,  input_h);
        hex_read(output, output_h);

        size_t words = maid_mp_words(1024);
        maid_mp_word e[words], d[words], N[words];
        maid_mp_read(words, e, e8, true);
        maid_mp_read(words, d, d8, true);
        maid_mp_read(words, N, N8, true);

        struct maid_rsa_key pub_k = {.exponent = e, .modulo = N};
        struct maid_rsa_key prv_k = {.exponent = d, .modulo = N};
        maid_pub_renew(pub, &pub_k);
        maid_pub_renew(prv, &prv_k);

        u8 tmp[128] = {0};
        memcpy(tmp, input, sizeof(input));
        maid_pub_apply(pub, tmp);

        if (memcmp(tmp, output, sizeof(output)) == 0)
        {
            maid_pub_apply(prv, tmp);
            ret = memcmp(tmp, input, sizeof(input)) == 0;
        }
    }

    return ret;
}

static u8
rsa_tests(void)
{
    u8 ret = 2;

    u8 zeros[128] = {0};
    struct maid_rsa_key zkey = {.exponent = (void *)zeros,
                                .modulo   = (void *)zeros};

    maid_pub *pub = maid_pub_new(maid_rsa_public,  &zkey, 1024);
    maid_pub *prv = maid_pub_new(maid_rsa_private, &zkey, 1024);

    size_t bits = 0;
    if (maid_pub_info(pub, &bits) == &maid_rsa_public  && bits == 1024 &&
        maid_pub_info(prv, &bits) == &maid_rsa_private && bits == 1024)
        ret -= 1;

    char *e[] =
        {"0000000000000000000000000000000000000000859e499b8a186c8ee6196954"
         "170eb8068593f0d764150a6d2e5d3fea7d9d0d33ac553eecd5c3f27a310115d2"
         "83e49377820195c8e67781b6f112a625b14b747fa4cc13d06eba0917246c775f"
         "5c732865701ae9349ea8729cde0bbade38204e63359a46e672a8d0a2fd530069"};
    char *d[] =
        {"27b7119a09edb827c13418c820b522a1ee08de0e4bb28106db6bb91498a3b361"
         "ab293af83fefcdd8a6bd2134ca4afacf64a0e33c014f48f47530f8847cc9185c"
         "bedec0d9238c8f1d5498f71c7c0cff48dc213421742e34350ca94007753cc0e5"
         "a783264cf49ff644ffea94253cfe86859acd2a2276ca4e7215f8ebaa2f188f51"};
    char *n[] =
        {"d0b750c8554b64c7a9d34d068e020fb52fea1b39c47971a359f0eec5da0437ea"
         "3fc94597d8dbff5444f6ce5a3293ac89b1eebb3f712b3ad6a06386e6401985e1"
         "9898715b1ea32ac03456fe1796d31ed4af389f4f675c23c421a125491e740fda"
         "c4322ec2d46ec945ddc349227b492191c9049145fb2f8c2998c486a840eac4d3"};
    char *input[] =
        {"5c7bce723cf4da053e503147242c60678c67e8c22467f0336b6d5c31f14088cb"
         "3d6cefb648db132cb32e95092f3d9bcd1cab51e68bd3a892ab359cdff556785a"
         "e06708633d39a0618f9d6d70f6bdeb6b777e7dd9acc41f19560c71a68479c8a0"
         "7b14fb9a4c765fd292ae56dd2f2143b62649cc70fb604fdc5cc1ade6e29de235"};
    char *output[] =
        {"6cf87c6a65925df6719eef5f1262edc6f8a0a0a0d21c535c64580745d9a268a9"
         "5b50ff3be24ba8b649ca47c3a760b71ddc3903f36aa1d98e87c53b3370be784b"
         "ffcb5bc180dea2acc15bb12e681c889b89b8f3de78050019dcdbb68c051b04b8"
         "80f0f8c4e855321ffed89767fc9d4a8a27a5d82ba450b2478c21e11843c2f539"};

    for (u8 i = 0; i < 1; i++)
        ret -= rsa_test(pub, prv, e[i], d[i], n[i], input[i], output[i]);

    maid_pub_del(pub);
    maid_pub_del(prv);

    return ret;
}

/* PKCS1 NIST test vectors */

static u8
pkcs1_test(struct maid_sign_def def, maid_pub *pub, maid_pub *prv,
           char *input_h, char *output_h)
{
    u8 ret = 0;

    if (pub && prv)
    {
        u8 input [256] = {0};
        u8 output[256] = {0};

        hex_read(input,  input_h);
        hex_read(output, output_h);

        maid_sign *s = maid_sign_new(def, pub, prv, 2048);
        maid_sign_renew(s, pub, prv);

        u8 tmp[256] = {0};
        memcpy(tmp, input, sizeof(input));
        maid_sign_generate(s, tmp);

        if (memcmp(tmp, output, sizeof(output)) == 0)
        {
            if (maid_sign_verify(s, tmp))
                ret = memcmp(tmp, input, sizeof(input)) == 0;
        }

        maid_sign_del(s);
    }

    return ret;
}

static u8
pkcs1_tests(void)
{
    u8 ret = 6;

    char *e[] = {
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000260445",
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000101957"};
    char *d[] = {
         "0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc938970"
         "9f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dc"
         "d65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f2"
         "19f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e"
         "0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56"
         "b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c"
         "8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773b"
         "af498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d",
         "057076fbab758efba2945f16d3456c21df4b7cfe1a8a762af8389e42e0b648f4"
         "d452d8bdffdf2097f75bc661efe939dd99c170c1672c9a0f21ad450347333fdc"
         "52f350d02ca1e6516cdbee38d3eb56b15f3f062b0d4f0901ed9a05a566917c5c"
         "108b20e0da091b8ca9da43b7b066d8c28d849068f6eb803d8e84ff243172c258"
         "cd7bd18858d2648dd7a55a2cb4db3feaf3171846e3e2c883f50a192be5ab4c79"
         "dd330584adcae17f1458bcb2ab43e3929cbef840e9999bf0eb5601e88ff8758d"
         "b564a756346d65d8c55f1b11b9b092fca7f6b2394ebc3109b3d02ec5a0967ea6"
         "45d127fe0fb9f9fa71637ac6f0b92671809f4aad1278a6cb5e8a7247fe53afdf"};
    char *n[] = {
         "cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72c"
         "c516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aef"
         "b920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a9681"
         "5b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30"
         "b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbf"
         "a2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11"
         "813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a"
         "8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d",
         "d39a426f8b81cd954f3df5512d6fcdb796457c172b6d510247e45ebecd1e0f7e"
         "8aa3253a61293a7b70094b70d65d73828719ef6aaabbb24e083b943be775b0bf"
         "3b5a0dc8388433de78e0c113ef7763f767ddd1542bcbdd9845919886ce20e289"
         "22754af2a733204bce9b5bd50140e18e5ba91e4800b50ef30ecd48b4ecded67a"
         "2f7be8bf7d7f14378a8c9ba0e6103d02f1685a334e46713033c89908da2e9f8b"
         "f72cb2a529281d4dc66799cc2a63c872b6bd5ffc1fa9ada236e7f8d5796dd972"
         "4e5e4ccadaf160de7f2d69c84009d31e952ac808c89a784be70cf60f42811928"
         "abdec6f896a0fa5fb164f9f4298a5a8831f6684dae31f2e76146d6be14c3ea7d"};

    char *input[] =
        {"c34b1a0d795dae5b88559191bb2c1cb75a5fd1d18b5002074560e6ad",
         "077877895a428028f60998b985550820025a2a42c0beab27165c0802d3098150",
         "8e5d03e53c9084db4e808148b55658d3a689ca4084dfc41bdf37bac5f8e11e83"
         "ab7eb6053bcb26be9b51ba03cac2b945",
         "68e7e5132d2d5985fc0c12f787ed3933fa96bfc4dd0e5fefd33336836d2eff85"
         "a652275e1cfd10f276e1c2f51c6d9b13a06399407baf2b3d9bf468eef0d2c4d8",
         "2c0a4d9ce74063da224a7955a045c05bdadf481125f5797fc2e03c59",
         "1ca543685a5698ea6b4f91afeae507e895497e0037c8f074300c96a8af0640b2"};
    char *output[] =
        {"27da4104eace1991e08bd8e7cfccd97ec48b896a0e156ce7bdc23fd570aaa9a0"
         "0ed015101f0c6261c7371ceca327a73c3cecfcf6b2d9ed920c9698046e25c89a"
         "db2360887d99983bf632f9e6eb0e5df60715902b9aeaa74bf5027aa246510891"
         "c74ae366a16f397e2c8ccdc8bd56aa10e0d01585e69f8c4856e76b53acfd3d78"
         "2b8171529008fa5eff030f46956704a3f5d9167348f37021fc277c6c0a8f93b8"
         "a23cfbf918990f982a56d0ed2aa08161560755adc0ce2c3e2ab2929f79bfc0b2"
         "4ff3e0ff352e6445d8a617f1785d66c32295bb365d61cfb107e9993bbd93421f"
         "2d344a86e4127827fa0d0b2535f9b1d547de12ba2868acdecf2cb5f92a6a159a",
         "6b8be97d9e518a2ede746ff4a7d91a84a1fc665b52f154a927650db6e7348c69"
         "f8c8881f7bcf9b1a6d3366eed30c3aed4e93c203c43f5528a45de791895747ad"
         "e9c5fa5eee81427edee02082147aa311712a6ad5fb1732e93b3d6cd23ffd46a0"
         "b3caf62a8b69957cc68ae39f9993c1a779599cdda949bdaababb77f248fcfeaa"
         "44059be5459fb9b899278e929528ee130facd53372ecbc42f3e8de2998425860"
         "406440f248d817432de687112e504d734028e6c5620fa282ca07647006cf0a2f"
         "f83e19a916554cc61810c2e855305db4e5cf893a6a96767365794556ff033359"
         "084d7e38a8456e68e21155b76151314a29875feee09557161cbc654541e89e42",
         "3974900bec3fcb081f0e5a299adf30d087aabaa633911410e87a4979bbe3fa80"
         "c3abcf221686399a49bc2f1e5ac40c35df1700e4b9cb7c805a896646573f4a57"
         "0a9704d2a2e6baee4b43d916906884ad3cf283529ea265e8fcb5cc1bdf7b7dee"
         "85941e4b4fb25c1fc7b951fb129ab393cb069be271c1d954da3c43674309f1d2"
         "12826fabb8e812de2d53d12597de040d32cb28c9f813159cb18c1b51f7a874cb"
         "f229cc222caeb98e35ec5e4bf5c5e22cc8528631f15117e8c2be6eac91f4070e"
         "ecdd07ecc6db6c46eaa65f472f2006988efef0b51c538c6e04d7519c8e3da4b1"
         "72b1e2761089ed3ad1197992ef37c168dc881c8b5f8bbfee919f7c7afd25b8fc",
         "148af61ed5ea8a87a08b3f403929bf8031db4fd3999b64409ba489f97a3ee520"
         "8ea4202d2ec18734f615003a51f77441085be6ac0f11810ffa2dad58f0e186d5"
         "520ac2b8a5d3966e8d2abb8074e13b50a4e7de83be10a66fdc7ca18118c5774f"
         "781212de9efebc6376fcdddc65a3b1b8f1ab31492fe478259ce719b3db587498"
         "d879a01dec96e8eabeb07ff7073f3f3eb446084955ca26329a791315a2c259d2"
         "25e26b2154b2047b21faba68115bfd962e5e24ec52d7c5d231e3044cbcd8c880"
         "4855703cbaa622b15b6ef78c7421a367166f1b02576c87360593da75b7189efa"
         "fd1082bd59f6857f1701f646c24d70c95273c49d5b11e6afe258821b55c1680c",
         "bb2969df7eac0f17e07992c00c8b561d1c21482f042a4fc95b739aace629a12f"
         "6086e399bff9aa71268203c1656ddfc890570bf49dc75d8a7bc510413135ef93"
         "1473b0ba77af4e5691970466bc2a5ef811b4eb94269173bb365ed28688c0078a"
         "11e0776ed7f539717209536079dc7af515386698c1e539dcf0b3c08e584e3bef"
         "987702aa02e5ab329725026dcf3fe64193a4e27451e5e77713908f07c742af0a"
         "2583a04c1f1a0ac4e9af5878a9c8e53ac1eba469ceef836f3f6eb9ee2625feaf"
         "933905c308c21aa75a76cde1d8bc41cf77beeed6919dd75d3834b3135a781cce"
         "01a04b468f339bbd21c74a323793c8f439e6df0f3dd4226e5ba8c712b29f7acc",
         "802fed875ef06dd2fad2ef123f14b360c0ed51eada42b4db56d8e62627a85a18"
         "fc15eacd2467d76e84efd1245e4e62ff9dd7c5dbcfb3c83d9cad6e0be064a3cb"
         "0100f3ffcd4c4025d654174a91a0b13767f5f8352305e61d54cfc61b9b801c57"
         "e1287e759ea1599b68bfcbba043d776e3f1e75887a1cc5d1ab878418bc15a356"
         "b479e6b4d12b7d49de850b2976b8113135c0df094ee476a5d6ba3b2a3a03ecf1"
         "f6e97f1e0c3ad17245221449a1e0b69b9441d97f596cffdbd93041b11757d19d"
         "6a3a07c7d204eb0f53ac94a5e3bc69d8c49cf1bfa4ee9c1e4c077c5a18296bef"
         "3a0db41524feee3cc83c2c2642c633436e635f11b43056c8c590f02ba3d2dfae"};

    u8 e8[256] = {0};
    u8 d8[256] = {0};
    u8 n8[256] = {0};

    hex_read(e8, e[0]);
    hex_read(d8, d[0]);
    hex_read(n8, n[0]);

    size_t words = maid_mp_words(2048);
    maid_mp_word ee[words];
    maid_mp_word dd[words];
    maid_mp_word nn[words];

    maid_mp_read(words, ee, e8, true);
    maid_mp_read(words, dd, d8, true);
    maid_mp_read(words, nn, n8, true);

    struct maid_rsa_key pub_key = {.exponent = ee, .modulo = nn};
    struct maid_rsa_key prv_key = {.exponent = dd, .modulo = nn};

    maid_pub *pub = maid_pub_new(maid_rsa_public,  &pub_key, 2048);
    maid_pub *prv = maid_pub_new(maid_rsa_private, &prv_key, 2048);

    struct maid_sign_def defs[] =
        {maid_pkcs1_v1_5_sha224,     maid_pkcs1_v1_5_sha256,
         maid_pkcs1_v1_5_sha384,     maid_pkcs1_v1_5_sha512,
         maid_pkcs1_v1_5_sha512_224, maid_pkcs1_v1_5_sha512_256};

    for (u8 i = 0; i < 4; i++)
        ret -= pkcs1_test(defs[i], pub, prv, input[i], output[i]);

    hex_read(e8, e[1]);
    hex_read(d8, d[1]);
    hex_read(n8, n[1]);

    maid_mp_read(words, ee, e8, true);
    maid_mp_read(words, dd, d8, true);
    maid_mp_read(words, nn, n8, true);

    maid_pub_renew(pub, &pub_key);
    maid_pub_renew(prv, &prv_key);
    for (u8 i = 4; i < 6; i++)
        ret -= pkcs1_test(defs[i], pub, prv, input[i], output[i]);

    maid_pub_del(pub);
    maid_pub_del(prv);

    return ret;
}

/* KAS FFC NIST test vectors */

static u8
dh_test(maid_kex *x, struct maid_dh_group *g, char *prv_h,
        char *pub_h, char *pub2_h, char *secret_h)
{
    u8 ret = 0;

    if (x && g)
    {
        u8 prv   [256] = {0};
        u8 pub   [256] = {0};
        u8 pub2  [256] = {0};
        u8 secret[256] = {0};

        hex_read(prv,    prv_h);
        hex_read(pub,    pub_h);
        hex_read(pub2,   pub2_h);
        hex_read(secret, secret_h);

        maid_kex_renew(x, g);

        u8 tmp[256] = {0};
        maid_kex_gpub(x, prv, tmp);
        if (memcmp(tmp, pub, sizeof(tmp)) == 0)
        {
            maid_kex_gsec(x, prv, pub2, tmp);
            ret = memcmp(tmp, secret, sizeof(tmp)) == 0;
        }
    }

    return ret;
}

static u8
dh_tests(void)
{
    u8 ret = 1;

    u8 zeros[256] = {0};
    struct maid_dh_group zgroup = {.generator = (void *)zeros,
                                   .modulo    = (void *)zeros};

    maid_kex *x = maid_kex_new(maid_dh, &zgroup, 2048);

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

    u8 g8[256] = {0};
    u8 p8[256] = {0};

    hex_read(g8, g[0]);
    hex_read(p8, p[0]);

    size_t words = maid_mp_words(2048);
    maid_mp_word gg[words];
    maid_mp_word pp[words];

    maid_mp_read(words, gg, g8, true);
    maid_mp_read(words, pp, p8, true);

    struct maid_dh_group group = {.generator = gg, .modulo = pp};

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
        ret -= dh_test(x, &group, prv[i], pub[i], pub2[i], secret[i]);

    maid_kex_del(x);

    return ret;
}

/* PEM encoding RFC 7468 examples, and OpenSSL generated keys */

static u8
import_tests(void)
{
    u8 ret = 8;

    const char *full =
        "Subject: CN=Atlantis\n"
        "Issuer: CN=Atlantis\n"
        "Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC\n"
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz\n"
        "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs\n"
        "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh\n"
        "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID\n"
        "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB\n"
        "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE\n"
        "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow\n"
        "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0\n"
        "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=\n"
        "-----END RSA PUBLIC KEY-----\n"
        "This is a test\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe\n"
        "kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U\n"
        "Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp\n"
        "-----END RSA PRIVATE KEY-----\n";

    u8 cert_type = MAID_IMPORT_PUBLIC_RSA;
    u8 cert_data[] =
        {0x30, 0x82, 0x01, 0x99, 0x30, 0x82, 0x01, 0x47, 0xa0, 0x03, 0x02,
         0x01, 0x02, 0x02, 0x01, 0x2a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
         0x03, 0x02, 0x1d, 0x05, 0x00, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f,
         0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x41, 0x74, 0x6c, 0x61,
         0x6e, 0x74, 0x69, 0x73, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30,
         0x37, 0x30, 0x39, 0x30, 0x33, 0x31, 0x30, 0x33, 0x38, 0x5a, 0x17,
         0x0d, 0x31, 0x33, 0x30, 0x37, 0x30, 0x39, 0x30, 0x33, 0x31, 0x30,
         0x33, 0x37, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
         0x55, 0x04, 0x03, 0x13, 0x08, 0x41, 0x74, 0x6c, 0x61, 0x6e, 0x74,
         0x69, 0x73, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
         0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00,
         0x30, 0x48, 0x02, 0x41, 0x00, 0xbb, 0xe0, 0x57, 0xa3, 0xe9, 0xa2,
         0x69, 0xb0, 0xc8, 0x1c, 0x7c, 0x7e, 0xca, 0xab, 0xaa, 0xce, 0xa3,
         0x61, 0x47, 0x29, 0xff, 0x5e, 0xd9, 0x09, 0x20, 0x81, 0xd5, 0x71,
         0x8b, 0x47, 0xbc, 0x85, 0xfe, 0x4b, 0x5c, 0x79, 0x12, 0xb8, 0x0c,
         0xa0, 0x77, 0xa1, 0xc9, 0xca, 0x68, 0xc5, 0xb1, 0x2b, 0x66, 0x65,
         0x51, 0xe0, 0x60, 0xaa, 0xd5, 0x2d, 0x9d, 0x88, 0xd9, 0x91, 0x15,
         0x90, 0x91, 0xb5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x89,
         0x30, 0x81, 0x86, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
         0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x20, 0x06, 0x03, 0x55,
         0x1d, 0x04, 0x01, 0x01, 0xff, 0x04, 0x16, 0x30, 0x14, 0x30, 0x0e,
         0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
         0x02, 0x01, 0x15, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d, 0x06, 0x03,
         0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06,
         0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01,
         0x05, 0x05, 0x07, 0x03, 0x03, 0x30, 0x35, 0x06, 0x03, 0x55, 0x1d,
         0x01, 0x04, 0x2e, 0x30, 0x2c, 0x80, 0x10, 0x34, 0x8c, 0xe9, 0xd2,
         0x4a, 0xe2, 0x07, 0x62, 0x69, 0xd5, 0xaf, 0x21, 0xc0, 0x77, 0x2c,
         0x0c, 0xa1, 0x15, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
         0x55, 0x04, 0x03, 0x13, 0x08, 0x41, 0x74, 0x6c, 0x61, 0x6e, 0x74,
         0x69, 0x73, 0x82, 0x01, 0x2a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
         0x03, 0x02, 0x1d, 0x05, 0x00, 0x03, 0x41, 0x00, 0xa8, 0xba, 0x1d,
         0x10, 0x5a, 0x34, 0x42, 0xf9, 0x47, 0x49, 0xf9, 0xea, 0x7b, 0xdf,
         0x72, 0x54, 0x0d, 0x69, 0x78, 0x83, 0x4f, 0x5e, 0xf8, 0xb9, 0xff,
         0xa5, 0xa2, 0x3c, 0xc0, 0xe2, 0x58, 0x55, 0x22, 0x77, 0x34, 0x20,
         0xbc, 0x29, 0x9d, 0x9d, 0x62, 0xcc, 0xbe, 0x0c, 0x94, 0x8f, 0x5e,
         0x09, 0x21, 0xe1, 0x55, 0x00, 0x47, 0x12, 0x9d, 0xae, 0x41, 0xd5,
         0xc9, 0x07, 0xe7, 0x79, 0x07, 0x28};

    u8 key_type = MAID_IMPORT_PRIVATE_RSA;
    u8 key_data[] =
        {0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
         0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62,
         0x00, 0x04, 0x9f, 0x52, 0xe5, 0xc0, 0xb3, 0x7f, 0x28, 0x16, 0x10,
         0x45, 0x51, 0xfa, 0x1d, 0xf2, 0x0c, 0x4f, 0x37, 0xc4, 0xa8, 0x93,
         0x95, 0xce, 0xd2, 0xde, 0x90, 0xb7, 0x21, 0xa7, 0x68, 0x62, 0xef,
         0xc7, 0x02, 0x68, 0xc6, 0x3c, 0xd4, 0x50, 0x65, 0x62, 0xcf, 0x09,
         0xf6, 0x5e, 0xe4, 0xad, 0xcf, 0x8c, 0xe1, 0xa0, 0x5e, 0x08, 0x66,
         0x05, 0x8d, 0xb6, 0xbe, 0x86, 0x25, 0xed, 0xb4, 0x95, 0x8f, 0x2f,
         0xbc, 0x9d, 0x94, 0x4f, 0xb9, 0x50, 0x6e, 0x14, 0x36, 0x49, 0xf7,
         0x12, 0x8b, 0x3c, 0x12, 0x26, 0x41, 0xca, 0x2f, 0x43, 0x56, 0xcc,
         0x9f, 0xcb, 0xd7, 0x9e, 0x8e, 0x1f, 0xbc, 0x01, 0x78, 0x29};

    const char *current = full;
    const char *endptr = NULL;

    int i = 0;
    do
    {
        struct maid_import *im = maid_import_pem(current, &endptr);

        if (im)
        {
            u8 type = MAID_IMPORT_UNKNOWN;
            u8 *data = NULL;
            size_t size = 0;

            switch (i)
            {
                case 0:
                    type = cert_type;
                    data = cert_data;
                    size = sizeof(cert_data);
                    break;
                case 1:
                    type = key_type;
                    data = key_data;
                    size = sizeof(key_data);
                    break;
            }

            if (i < 2)
            {
                ret -= im->type == type;
                ret -= memcmp(im->data, data, size) == 0;
                ret -= im->size == size;
            }
        }
        else
            break;

        maid_import_free(im);
        current = endptr;
        i++;
    } while (endptr && *endptr != '\0');

    /* Tests with actual keys */

    /* SHA-256 of "test\n" */
    const u8 hash[] = {
        0xf2, 0xca, 0x1b, 0xb6, 0xc7, 0xe9, 0x07, 0xd0, 0x6d, 0xaf, 0xe4, 0x68,
        0x7e, 0x57, 0x9f, 0xce, 0x76, 0xb3, 0x7e, 0x4e, 0x93, 0xb7, 0x60, 0x50,
        0x22, 0xda, 0x52, 0xe6, 0xcc, 0xc2, 0x6f, 0xd2
    };
    const u8 sign[] = {
        0xc5, 0x56, 0xd6, 0x91, 0x88, 0xc5, 0x61, 0xe6, 0x9f, 0x57, 0xd7, 0x33,
        0x40, 0x51, 0xd0, 0x4c, 0xa2, 0x4f, 0x95, 0xc7, 0xcb, 0x12, 0x64, 0x50,
        0x17, 0xb0, 0x68, 0xa0, 0x51, 0x81, 0x84, 0x87, 0xe6, 0x5b, 0x89, 0x7e,
        0x07, 0x2d, 0x0a, 0xa2, 0x49, 0xdb, 0x9b, 0x44, 0x1b, 0xdc, 0xdc, 0x3d,
        0xd6, 0x64, 0x20, 0xa7, 0x3e, 0x9c, 0xfa, 0x9b, 0xeb, 0x3c, 0x72, 0x36,
        0x3f, 0x48, 0x48, 0x4e
    };

    /* Generated with OpenSSL */
    const char *public =
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "MEgCQQDOrAiCLeywlbUCMIh5YITLZJI4JNQ9lqaTGYPRs4vHrQP19vDiieCX1rVm\n"
        "7Z6EPqGqU0zWep/FBI7apVej9KedAgMBAAE=\n"
        "-----END RSA PUBLIC KEY-----\n";
    const char *private =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOwIBAAJBAM6sCIIt7LCVtQIwiHlghMtkkjgk1D2WppMZg9Gzi8etA/X28OKJ\n"
        "4JfWtWbtnoQ+oapTTNZ6n8UEjtqlV6P0p50CAwEAAQJBALGjOGT8KDbXVo+dO5Bo\n"
        "H3va47sSHMMbG+3PvneeBYUHa6WnVIlMYI0HcQvTEqVuMN8PDf8nTvVsCW+WCtms\n"
        "NxkCIQDqfmtUG02nXGZLMf9xRqouk+SekcQ56ILQYn+7+LIK6wIhAOGgZbWNhe3p\n"
        "cdLITb1LZE1cgtqrLeT0Imux4BmqhOWXAiB+7HiJqNGqYfAYiXJ7TMV2uqRHVB0D\n"
        "Px/3TSlYhC9SiwIhALYW996078CZJVZid3Ls1G8m2ShW/DwJ13mo3V55YrXTAiBm\n"
        "qeknz1OVyy/mtSahY89+tfIWnCbb9r9VW9+zt+HQaA==\n"
        "-----END RSA PRIVATE KEY-----\n";
    const char *public2 =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM6sCIIt7LCVtQIwiHlghMtkkjgk1D2W\n"
        "ppMZg9Gzi8etA/X28OKJ4JfWtWbtnoQ+oapTTNZ6n8UEjtqlV6P0p50CAwEAAQ==\n"
        "-----END PUBLIC KEY-----\n";
    const char *private2 =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAzqwIgi3ssJW1AjCI\n"
        "eWCEy2SSOCTUPZamkxmD0bOLx60D9fbw4ongl9a1Zu2ehD6hqlNM1nqfxQSO2qVX\n"
        "o/SnnQIDAQABAkEAsaM4ZPwoNtdWj507kGgfe9rjuxIcwxsb7c++d54FhQdrpadU\n"
        "iUxgjQdxC9MSpW4w3w8N/ydO9WwJb5YK2aw3GQIhAOp+a1QbTadcZksx/3FGqi6T\n"
        "5J6RxDnogtBif7v4sgrrAiEA4aBltY2F7elx0shNvUtkTVyC2qst5PQia7HgGaqE\n"
        "5ZcCIH7seImo0aph8BiJcntMxXa6pEdUHQM/H/dNKViEL1KLAiEAthb33rTvwJkl\n"
        "VmJ3cuzUbybZKFb8PAnXeajdXnlitdMCIGap6SfPU5XLL+a1JqFjz3618hacJtv2\n"
        "v1Vb37O34dBo\n"
        "-----END PRIVATE KEY-----\n";

    const char *pubs[] = {public,  public2};
    const char *prvs[] = {private, private2};

    for (u8 i = 0; i < 2; i++)
    {
        const char *endptr = NULL;
        struct maid_import *im  = maid_import_pem(pubs[i], &endptr);
        struct maid_import *im2 = maid_import_pem(prvs[i], &endptr);

        u8 buffer[64] = {0};
        maid_pub *pub = NULL, *prv = NULL;
        maid_sign *s = NULL;
        if (im && im2)
        {
            pub = maid_import_pub(im);
            prv = maid_import_pub(im2);
        }
        if (pub && prv)
            s = maid_sign_new(maid_pkcs1_v1_5_sha256, pub, prv, 512);
        if (s)
        {
            memcpy(buffer, hash, sizeof(hash));
            maid_sign_generate(s, buffer);
            if (memcmp(buffer, sign, sizeof(sign)) == 0 &&
                maid_sign_verify(s, buffer))
                ret -= memcmp(buffer, hash, sizeof(hash)) == 0;
        }

        maid_import_free(im);
        maid_import_free(im2);
        maid_pub_del(pub);
        maid_pub_del(prv);
        maid_sign_del(s);
    }

    return ret;
}

extern int
main(void)
{
    u16 ret = 0;

    /* Utilities */

    ret += mem_tests();
    ret += mp_tests();

    /* Symmetric cryptography */

    ret += aes_tests();
    ret += aes_ctr_tests();
    ret += aes_gcm_tests();

    ret += chacha_tests();
    ret += poly1305_tests();
    ret += chacha20poly1305_tests();

    ret += ctr_drbg_tests();
    ret += sha2_tests();

    ret += hmac_tests();

    /* Asymmetric cryptography */

    ret += rsa_tests();
    ret += pkcs1_tests();
    ret += dh_tests();

    /* Interfaces */

    ret += import_tests();

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
