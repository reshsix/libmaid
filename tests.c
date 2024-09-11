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
    u8 ret = 4;

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

   return ret;
}

/* Multiprecision utilities */

static void
mp_test(size_t words, u32 *val, u32 *a, u32 *b, u32 *c,
        size_t ia, size_t ib, size_t ic)
{
    for (u8 i = 0; i < words; i++)
    {
        maid_mem_write(a, i, sizeof(u32), false, val[(ia * words) + i]);
        maid_mem_write(b, i, sizeof(u32), false, val[(ib * words) + i]);
        maid_mem_write(c, i, sizeof(u32), false, val[(ic * words) + i]);
    }
}

static u8
mp_tests(void)
{
    u8 ret = 22;

    u32 zeros[2] = {0};
    u32 val[] = {0x0de1f1ed, 0xcafebabe, 0xc0d1f1ed, 0x0011b1d0,
                 0xdeadbea7, 0xcafebe7a, 0x9f7fb094, 0xcb10704b,
                 0x919dbea7, 0x0011b58d, 0x00000000, 0x233b7d4e,
                 0x000119db, 0x00000000, 0xd16a1569, 0x4bc9057c,
                 0x00000b78, 0x00000000, 0xa6135bd5, 0x000f689a,
                 0xe65b0ddd, 0x44067ebe};

    u32 a[2] = {0};
    u32 b[2] = {0};
    u32 c[2] = {0};

    mp_test(2, val, a, b, c, 0, 1, 0);
    ret -= maid_mp_cmp(2, a, b)    == -1;
    ret -= maid_mp_cmp(2, b, a)    ==  1;
    ret -= maid_mp_cmp(2, a, a)    ==  0;
    ret -= maid_mp_cmp(2, a, NULL) == -1;

    maid_mp_mov(2, a, NULL);
    ret -= memcmp(a, zeros, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 0, 2, 2);
    maid_mp_mov(2, a, b);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 2, 1, 3);
    maid_mp_add(2, a, b);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_add(2, a, NULL);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 3, 0, 4);
    maid_mp_sub(2, a, b);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_sub(2, a, NULL);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 4, 0, 5);
    maid_mp_shl(2, a, 33);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_shl(2, a, 128);
    ret -= memcmp(a, zeros, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 5, 0, 6);
    maid_mp_shr(2, a, 45);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_shl(2, a, 128);
    ret -= memcmp(a, zeros, sizeof(u32) * 2) == 0;

    u32 tmp[2] = {0};
    u32 tmp2[2] = {0};
    u32 tmp3[2] = {0};

    mp_test(2, val, a, b, c, 0, 1, 7);
    maid_mp_mul(2, a, b, tmp);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_mul(2, a, NULL, tmp);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 0, 1, 8);
    maid_mp_div(2, a, b, tmp, tmp2);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_div(2, a, NULL, tmp2, tmp);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 0, 1, 9);
    maid_mp_mod(2, a, b, tmp3, tmp, tmp2);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_mod(2, a, NULL, tmp2, tmp3, tmp);
    ret -= memcmp(a, zeros, sizeof(u32) * 2) == 0;

    mp_test(2, val, a, b, c, 0, 1, 10);
    maid_mp_exp(2, a, b, tmp3, tmp2, tmp);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;
    maid_mp_exp(2, a, NULL, tmp, tmp3, tmp2);
    ret -= memcmp(a, c, sizeof(u32) * 2) == 0;

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

        if (ae)
        {
            maid_aead_renew(ae, key, nonce);
            maid_aead_update(ae, ad, length2);
            maid_aead_crypt(ae, input, length, false);

            u8 tag2[16] = {0};
            maid_aead_digest(ae, tag2);

            if (memcmp(input, output, length)  == 0 &&
                memcmp(tag2, tag, sizeof(tag)) == 0 )
                ret = 1;
        }
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

extern int
main(void)
{
    u8 ret = 0;

    /* Utilities */

    ret += mem_tests();
    ret += mp_tests();

    /* Algorithms */

    ret += aes_tests();
    ret += aes_ctr_tests();
    ret += aes_gcm_tests();

    ret += chacha_tests();
    ret += poly1305_tests();
    ret += chacha20poly1305_tests();

    ret += ctr_drbg_tests();
    ret += sha2_tests();

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
