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

#include <maid/crypto/aes.h>
#include <maid/crypto/gmac.h>
#include <maid/crypto/chacha.h>
#include <maid/crypto/poly1305.h>

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/mac.h>
#include <maid/aead.h>

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

/* AES NIST SP 800-38A vectors */

static u8
aes_test(struct maid_block_def def, char *key_h,
         char *input_h, char *output_h, bool decrypt)
{
    u8 ret = 0;

    u8    key[32] = {0};
    u8  input[16] = {0};
    u8 output[16] = {0};

    hex_read(key,    key_h);
    hex_read(input,  input_h);
    hex_read(output, output_h);

    u8 iv[16] = {0};
    maid_block *bl = maid_block_new(def, key, iv);
    if (bl)
    {
        maid_block_ecb(bl, input, decrypt);
        if (memcmp(input, output, sizeof(output)) == 0)
            ret = 1;
    }
    maid_block_del(bl);

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

    for (u8 i = 0; i < 4; i++)
    {
        ret -= aes_test(maid_aes_128, key128, block[i], cipher128[i], false);
        ret -= aes_test(maid_aes_128, key128, cipher128[i], block[i], true);

        ret -= aes_test(maid_aes_192, key192, block[i], cipher192[i], false);
        ret -= aes_test(maid_aes_192, key192, cipher192[i], block[i], true);

        ret -= aes_test(maid_aes_256, key256, block[i], cipher256[i], false);
        ret -= aes_test(maid_aes_256, key256, cipher256[i], block[i], true);
    }

    return ret;
}

/* AES-CTR NIST SP 800-38A vectors */

static u8
aes_ctr_test(struct maid_block_def def, char *key_h, char *iv_h,
             char *input_h, char *output_h)
{
    u8 ret = 0;

    u8    key[32] = {0};
    u8     iv[16] = {0};
    u8  input[64] = {0};
    u8 output[64] = {0};

    hex_read(key,   key_h);
    hex_read(iv,    iv_h);
    hex_read(input, input_h);

    size_t length = hex_read(output, output_h);

    maid_block *bl = maid_block_new(def, key, iv);
    if (bl)
    {
        maid_block_ctr(bl, input, length);
        if (memcmp(input, output, length) == 0)
            ret = 1;
    }
    maid_block_del(bl);

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

    ret -= aes_ctr_test(maid_aes_128, key128, iv, block, cipher128);
    ret -= aes_ctr_test(maid_aes_128, key128, iv, cipher128, block);

    ret -= aes_ctr_test(maid_aes_192, key192, iv, block, cipher192);
    ret -= aes_ctr_test(maid_aes_192, key192, iv, cipher192, block);

    ret -= aes_ctr_test(maid_aes_256, key256, iv, block, cipher256);
    ret -= aes_ctr_test(maid_aes_256, key256, iv, cipher256, block);

    return ret;
}

/* AES-GCM GCM Spec vectors */

static u8
aes_gcm_test(struct maid_aead_def def, char *key_h, char *nonce_h, char *ad_h,
             char *input_h, char *output_h, char *tag_h)
{
    u8 ret = 0;

    u8    key[32] = {0};
    u8  nonce[64] = {0};
    u8     ad[32] = {0};
    u8  input[64] = {0};
    u8 output[64] = {0};
    u8    tag[16] = {0};
    u8   tag2[16] = {0};

    hex_read(key,   key_h);
    hex_read(input, input_h);
    hex_read(tag2,  tag_h);

    size_t length  = hex_read(nonce,  nonce_h);
    size_t length2 = hex_read(output, output_h);
    size_t length3 = hex_read(ad,     ad_h);

    /* Allows for variable length IVs */
    u8 iv[16] = {0};
    if (length == 12)
    {
        memcpy(iv, nonce, 12);
        iv[15] = 0x1;
    }
    else
    {
        /* Encrypted nonce is added in the end of AEAD construction,
         * but not on GHASH, so make it decrypted zeros */
        maid_block *blk = maid_block_new(def.c_def.block, key, iv);
        if (blk)
            maid_block_ecb(blk, iv, true);
        maid_block_del(blk);

        /* Specs want it GHASHed with length, so it's simpler
         * to use the AEAD construction already */
        maid_aead *ae = maid_aead_new(def, key, iv);
        if (ae)
        {
            maid_aead_crypt(ae, nonce, length, true);
            maid_aead_digest(ae, iv);
        }
        maid_aead_del(ae);
    }

    /* The actual test */
    maid_aead *ae = maid_aead_new(def, key, iv);
    if (ae)
    {
        maid_aead_update(ae, ad, length3);
        maid_aead_crypt(ae, input, length2, false);
        maid_aead_digest(ae, tag);

        if (memcmp(input, output, length2)  == 0 &&
            memcmp(tag, tag2, sizeof(tag2)) == 0 )
            ret = 1;
    }
    maid_aead_del(ae);

    return ret;
}

static u8
aes_gcm_tests(void)
{
    u8 ret = 18;

    char  *key_z = (char *)32;
    char   key[] = "feffe9928665731c6d6a8f9467308308"
                   "feffe9928665731c6d6a8f9467308308";

    char      *iv_z = (char *)12;
    char    iv_96[] = "cafebabefacedbaddecaf888";
    char iv_small[] = "cafebabefacedbad";
    char   iv_big[] = "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d"
                      "2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a"
                      "57a637b39b";

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

    struct maid_aead_def defs[] = {maid_aes_gcm_128,
                                   maid_aes_gcm_192,
                                   maid_aes_gcm_256};
    char **ciphers[] = {cipher128, cipher192, cipher256};
    char    **tags[] = {tag128, tag192, tag256};

    for (u8 i = 0; i < 3; i++)
    {
        ret -= aes_gcm_test(defs[i], key_z, iv_z,     "", "",
                            "",            tags[i][0]);
        ret -= aes_gcm_test(defs[i], key_z, iv_z,     "", data_z,
                            ciphers[i][0], tags[i][1]);
        ret -= aes_gcm_test(defs[i], key,   iv_96,    "", data,
                            ciphers[i][1], tags[i][2]),
        ret -= aes_gcm_test(defs[i], key,   iv_96,    ad, data_s,
                            ciphers[i][2], tags[i][3]);
        ret -= aes_gcm_test(defs[i], key,   iv_small, ad, data_s,
                            ciphers[i][3], tags[i][4]);
        ret -= aes_gcm_test(defs[i], key,   iv_big,   ad, data_s,
                            ciphers[i][4], tags[i][5]);
    }

    return ret;
}

/* Chacha20 RFC8439 vectors */

static u8
chacha_test(char *key_h, char *nonce_h, u32 counter,
            char *input_h, char *output_h)
{
    u8 ret = 0;

    u8      key[32] = {0};
    u8    nonce[16] = {0};
    u8  input[1024] = {0};
    u8 output[1024] = {0};

    hex_read(key,   key_h);
    hex_read(nonce, nonce_h);
    hex_read(input, input_h);

    size_t length = hex_read(output, output_h);

    maid_stream *st = maid_stream_new(maid_chacha20, key, nonce, counter);
    if (st)
    {
        maid_stream_xor(st, input, length);
        if (memcmp(input, output, length) == 0)
            ret = 1;
    }
    maid_stream_del(st);

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

    for (u8 i = 0; i < 11; i++)
        ret -= chacha_test(keys[i], nonces[i], counters[i],
                           datas[i], ciphers[i]);

    return ret;
}

/* Poly1305 RFC8439 vectors */

static u8
poly1305_test(char *key_h, char *input_h, char *tag_h)
{
    u8 ret = 0;

    u8     key[32] = {0};
    u8 input[1024] = {0};
    u8     tag[16] = {0};
    u8    tag2[16] = {0};

    hex_read(key,  key_h);
    hex_read(tag2, tag_h);

    size_t length = hex_read(input, input_h);

    maid_mac *m = maid_mac_new(maid_poly1305, key);
    if (m)
    {
        maid_mac_update(m, input, length);
        maid_mac_digest(m, tag);
        if (memcmp(tag, tag2, sizeof(tag2)) == 0)
            ret = 1;
    }
    maid_mac_del(m);

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

    for (u8 i = 0; i < 11; i++)
        ret -= poly1305_test(keys[i], datas[i], tags[i]);

    return ret;
}

/* Chacha20Poly1305 RFC8439 vectors */

static u8
chacha20poly1305_test(char *key_h, char *nonce_h, char *ad_h,
                      char *input_h, char *output_h, char *tag_h,
                      bool decrypt)
{
    u8 ret = 0;

    u8      key[32] = {0};
    u8    nonce[12] = {0};
    u8       ad[16] = {0};
    u8  input[1024] = {0};
    u8 output[1024] = {0};
    u8      tag[16] = {0};
    u8     tag2[16] = {0};

    hex_read(key,    key_h);
    hex_read(nonce,  nonce_h);
    hex_read(output, output_h);
    hex_read(tag2,   tag_h);

    size_t length  = hex_read(input, input_h);
    size_t length2 = hex_read(ad,    ad_h);

    maid_aead *ae = maid_aead_new(maid_chacha20poly1305, key, nonce);
    if (ae)
    {
        maid_aead_update(ae, ad, length2);
        maid_aead_crypt(ae, input, length, decrypt);
        maid_aead_digest(ae, tag);

        if (memcmp(input, output, length)   == 0 &&
            memcmp(tag, tag2, sizeof(tag2)) == 0 )
            ret = 1;
    }
    maid_aead_del(ae);

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

    for (u8 i = 0; i < 2; i++)
        ret -= chacha20poly1305_test(keys[i], nonces[i], ads[i], inputs[i],
                                     outputs[i], tags[i], modes[i]);

    return ret;
}

extern int
main(void)
{
    u8 ret = 0;

    ret += aes_tests();
    ret += aes_ctr_tests();
    ret += aes_gcm_tests();

    ret += chacha_tests();
    ret += poly1305_tests();
    ret += chacha20poly1305_tests();

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
