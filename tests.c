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

#include <maid/utils.h>

#include <maid/crypto/aes.h>
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
    size_t length = strlen(hex) / 2;

    for (size_t i = 0; i < length; i++)
    {
        data[i] = (hex_digit(hex[(i * 2) + 0]) << 4) |
                  (hex_digit(hex[(i * 2) + 1]) << 0) ;
    }

    return length;
}

static u32 failures = 0;
static void
fail_test(char *file, char *num, char *op)
{
    fprintf(stderr, "- %s Test %s from %s Failed\n", op, num, file);
    failures++;
}

/* AES NIST SP 800-38A vectors */

static void
aes_test(struct maid_block_def def, char *file, char *num,
         char *key_h, char *input_h, char *output_h, bool decrypt)
{
    u8 key[32], input[16], output[16];
    hex_read(key,    key_h);
    hex_read(input,  input_h);
    hex_read(output, output_h);

    u8 iv[16] = {0};
    maid_block *bl = maid_block_new(def, key, iv);
    if (bl)
    {
        maid_block_ecb(bl, input, decrypt);
        if (memcmp(input, output, sizeof(output)) != 0)
            fail_test(file, num, (decrypt) ? "Decryption" : "Encryption");
    }
    maid_block_del(bl);

    maid_mem_clear(key,    sizeof(key));
    maid_mem_clear(input,  sizeof(input));
    maid_mem_clear(output, sizeof(output));
}

static void
aes_tests(void)
{
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.1", "1",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "6bc1bee22e409f96e93d7e117393172a",
             "3ad77bb40d7a3660a89ecaf32466ef97", false);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.1", "2",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "ae2d8a571e03ac9c9eb76fac45af8e51",
             "f5d3d58503b9699de785895a96fdbaaf", false);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.1", "3",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "30c81c46a35ce411e5fbc1191a0a52ef",
             "43b1cd7f598ece23881b00e3ed030688", false);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.1", "4",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "f69f2445df4f9b17ad2b417be66c3710",
             "7b0c785e27e8ad3f8223207104725dd4", false);

    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.2", "1",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "3ad77bb40d7a3660a89ecaf32466ef97",
             "6bc1bee22e409f96e93d7e117393172a", true);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.2", "2",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "f5d3d58503b9699de785895a96fdbaaf",
             "ae2d8a571e03ac9c9eb76fac45af8e51", true);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.2", "3",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "43b1cd7f598ece23881b00e3ed030688",
             "30c81c46a35ce411e5fbc1191a0a52ef", true);
    aes_test(maid_aes_128, "NIST SP 800-38A-F.1.2", "4",
             "2b7e151628aed2a6abf7158809cf4f3c",
             "7b0c785e27e8ad3f8223207104725dd4",
             "f69f2445df4f9b17ad2b417be66c3710", true);

    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.3", "1",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "6bc1bee22e409f96e93d7e117393172a",
             "bd334f1d6e45f25ff712a214571fa5cc", false);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.3", "2",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "ae2d8a571e03ac9c9eb76fac45af8e51",
             "974104846d0ad3ad7734ecb3ecee4eef", false);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.3", "3",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "30c81c46a35ce411e5fbc1191a0a52ef",
             "ef7afd2270e2e60adce0ba2face6444e", false);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.3", "4",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "f69f2445df4f9b17ad2b417be66c3710",
             "9a4b41ba738d6c72fb16691603c18e0e", false);

    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.4", "1",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "bd334f1d6e45f25ff712a214571fa5cc",
             "6bc1bee22e409f96e93d7e117393172a", true);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.4", "2",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "974104846d0ad3ad7734ecb3ecee4eef",
             "ae2d8a571e03ac9c9eb76fac45af8e51", true);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.4", "3",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "ef7afd2270e2e60adce0ba2face6444e",
             "30c81c46a35ce411e5fbc1191a0a52ef", true);
    aes_test(maid_aes_192, "NIST SP 800-38A-F.1.4", "4",
             "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
             "9a4b41ba738d6c72fb16691603c18e0e",
             "f69f2445df4f9b17ad2b417be66c3710", true);

    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.5", "1",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8", false);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.5", "2",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "591ccb10d410ed26dc5ba74a31362870", false);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.5", "3",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "b6ed21b99ca6f4f9f153e7b1beafed1d", false);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.5", "4",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f69f2445df4f9b17ad2b417be66c3710",
            "23304b7a39f9f3ff067d8d8f9e24ecc7", false);

    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.6", "1",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
            "6bc1bee22e409f96e93d7e117393172a", true);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.6", "2",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "591ccb10d410ed26dc5ba74a31362870",
            "ae2d8a571e03ac9c9eb76fac45af8e51", true);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.6", "3",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "b6ed21b99ca6f4f9f153e7b1beafed1d",
            "30c81c46a35ce411e5fbc1191a0a52ef", true);
    aes_test(maid_aes_256, "NIST SP 800-38A-F.1.6", "4",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "23304b7a39f9f3ff067d8d8f9e24ecc7",
            "f69f2445df4f9b17ad2b417be66c3710", true);
}

/* Chacha20 RFC8439 vectors */

static void
chacha_test(char *file, char *num, char *key_h, char *nonce_h, u32 counter,
            char *input_h, char *output_h)
{
    u8 key[32], nonce[16], input[1024], output[1024];
    hex_read(key,   key_h);
    hex_read(nonce, nonce_h);
    hex_read(input, input_h);
    size_t length = hex_read(output, output_h);

    maid_stream *st = maid_stream_new(maid_chacha20, key, nonce, counter);
    if (st)
    {
        maid_stream_xor(st, input, length);
        if (memcmp(input, output, length) != 0)
            fail_test(file, num, "Encryption");
    }
    maid_stream_del(st);

    maid_mem_clear(key,    sizeof(key));
    maid_mem_clear(nonce,  sizeof(nonce));
    maid_mem_clear(input,  sizeof(input));
    maid_mem_clear(output, sizeof(output));
}

static void
chacha_tests(void)
{
    chacha_test("RFC8439-2.4.2", "0",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000000000000004a00000000", 1,
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e",
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42874d");

    chacha_test("RFC8439-A.1", "1",
           "0000000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000000", 0,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
           "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    chacha_test("RFC8439-A.1", "2",
           "0000000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000000", 1,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
           "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
    chacha_test("RFC8439-A.1", "3",
           "0000000000000000000000000000000000000000000000000000000000000001",
           "000000000000000000000000", 1,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
           "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");
    chacha_test("RFC8439-A.1", "4",
           "00ff000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000000", 2,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
           "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");
    chacha_test("RFC8439-A.1", "5",
           "0000000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000002", 0,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
           "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");

    chacha_test("RFC8439-A.2", "1",
           "0000000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000000", 0,
           "0000000000000000000000000000000000000000000000000000000000000000"
           "0000000000000000000000000000000000000000000000000000000000000000",
           "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
           "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    chacha_test("RFC8439-A.2", "2",
           "0000000000000000000000000000000000000000000000000000000000000001",
           "000000000000000000000002", 1,
           "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
           "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
           "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
           "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
           "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
           "206f6620616e204945544620616374697669747920697320636f6e7369646572"
           "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
           "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
           "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
           "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
           "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
           "207768696368206172652061646472657373656420746f",
           "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec"
           "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d"
           "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
           "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a"
           "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d"
           "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
           "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c"
           "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b"
           "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
           "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6"
           "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab"
           "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");
    chacha_test("RFC8439-A.2", "3",
           "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
           "000000000000000000000002", 42,
           "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
           "7665730a446964206779726520616e642067696d626c6520696e207468652077"
           "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
           "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
           "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
           "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
           "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
           "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");

    chacha_test("RFC8439-A.4", "1",
           "0000000000000000000000000000000000000000000000000000000000000000",
           "000000000000000000000000", 0,
           "0000000000000000000000000000000000000000000000000000000000000000",
           "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7");
    chacha_test("RFC8439-A.4", "2",
           "0000000000000000000000000000000000000000000000000000000000000001",
           "000000000000000000000002", 0,
           "0000000000000000000000000000000000000000000000000000000000000000",
           "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739");
    chacha_test("RFC8439-A.4", "3",
           "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
           "000000000000000000000002", 0,
           "0000000000000000000000000000000000000000000000000000000000000000",
           "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae");
}

/* Poly1305 RFC8439 vectors */

static void
poly1305_test(char *file, char *num, char *key_h, char *input_h, char *tag_h)
{
    u8 key[32], input[1024], tag[16], output[16];
    hex_read(key,     key_h);
    hex_read(output,  tag_h);
    size_t length = hex_read(input, input_h);

    maid_mac *m = maid_mac_new(maid_poly1305, key);
    if (m)
    {
        maid_mac_update(m, input, length);
        maid_mac_digest(m, tag);
        if (memcmp(tag, output, sizeof(output)) != 0)
            fail_test(file, num, "Authentication");
    }
    maid_mac_del(m);

    maid_mem_clear(key,    sizeof(key));
    maid_mem_clear(input,  sizeof(input));
    maid_mem_clear(tag,    sizeof(tag));
    maid_mem_clear(output, sizeof(output));
}

static void
poly1305_tests(void)
{
    poly1305_test("RFC8439-A.3", "1",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000");
    poly1305_test("RFC8439-A.3", "2",
            "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
            "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
            "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
            "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
            "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
            "206f6620616e204945544620616374697669747920697320636f6e7369646572"
            "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
            "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
            "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
            "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
            "207768696368206172652061646472657373656420746f",
            "36e5f6b5c5e06070f0efca96227a863e");
    poly1305_test("RFC8439-A.3", "3",
            "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
            "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
            "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
            "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
            "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
            "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
            "206f6620616e204945544620616374697669747920697320636f6e7369646572"
            "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
            "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
            "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
            "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
            "207768696368206172652061646472657373656420746f",
            "f3477e7cd95417af89a6b8794c310cf0");
    poly1305_test("RFC8439-A.3", "4",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
            "7665730a446964206779726520616e642067696d626c6520696e207468652077"
            "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
            "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
            "4541669a7eaaee61e708dc7cbcc5eb62");
    poly1305_test("RFC8439-A.3", "5",
            "0200000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffff",
            "03000000000000000000000000000000");
    poly1305_test("RFC8439-A.3", "6",
            "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
            "03000000000000000000000000000000");
    poly1305_test("RFC8439-A.3", "7",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
            "11000000000000000000000000000000",
            "05000000000000000000000000000000");
    poly1305_test("RFC8439-A.3", "8",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
            "01010101010101010101010101010101",
            "00000000000000000000000000000000");
    poly1305_test("RFC8439-A.3", "9",
            "0200000000000000000000000000000000000000000000000000000000000000",
            "fdffffffffffffffffffffffffffffff",
            "faffffffffffffffffffffffffffffff");
    poly1305_test("RFC8439-A.3", "10",
            "0100000000000000040000000000000000000000000000000000000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
            "0000000000000000000000000000000001000000000000000000000000000000",
            "14000000000000005500000000000000");
    poly1305_test("RFC8439-A.3", "11",
            "0100000000000000040000000000000000000000000000000000000000000000",
            "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
            "00000000000000000000000000000000",
            "13000000000000000000000000000000");
}

/* Chacha20Poly1305 RFC8439 vectors */

static void
chacha20poly1305_test(char *file, char *num, char *key_h, char *input_h,
                      char *ad_h, char *nonce_h, char *output_h, char *tag_h,
                      bool decrypt)
{
    u8 key[32], input[128], ad[16], nonce[12],
       output[128], tag[16], tag2[16];
    hex_read(key,    key_h);
    hex_read(nonce,  nonce_h);
    hex_read(output, output_h);
    hex_read(tag2,   tag_h);

    size_t length = hex_read(input, input_h);
    size_t length2 = hex_read(ad, ad_h);

    maid_aead *ae = maid_aead_new(maid_chacha20poly1305, key, nonce);
    if (ae)
    {
        maid_aead_update(ae, ad, length2);
        maid_aead_crypt(ae, input, length, decrypt);
        maid_aead_digest(ae, tag);

        if (memcmp(input, output, length)   != 0 ||
            memcmp(tag, tag2, sizeof(tag2)) != 0 )
            fail_test(file, num, "Authenticated Encryption");
    }
    maid_aead_del(ae);

    maid_mem_clear(key,    sizeof(key));
    maid_mem_clear(input,  sizeof(input));
    maid_mem_clear(ad,     sizeof(ad));
    maid_mem_clear(nonce,  sizeof(nonce));
    maid_mem_clear(output, sizeof(output));
    maid_mem_clear(tag,    sizeof(tag));
    maid_mem_clear(tag2,   sizeof(tag2));
}

static void
chacha20poly1305_tests(void)
{
    chacha20poly1305_test("RFC8439-2.8.2", "0",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069742e",
            "50515253c0c1c2c3c4c5c6c7",
            "070000004041424344454647",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691",
            false);
    chacha20poly1305_test("RFC8439-A.5", "0",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
            "a6ad5cb4022b02709b",
            "f33388860000000000004e91",
            "000000000102030405060708",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
            "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
            "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
            "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
            "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
            "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
            "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
            "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
            "726573732e2fe2809d",
            "eead9d67890cbb22392336fea1851f38",
            true);
}

/* Legacy tests */

static bool
aead_test(struct maid_aead_def def, u8 *key, u8 *nonce,
          u8 *ad, size_t ad_s, u8 *data, size_t data_s,
          u8 *cipher, u8 *tag, size_t tag_s)
{
    bool ret = false;

    maid_aead *ae = maid_aead_new(def, key, nonce);
    maid_aead *ae2 = maid_aead_new(def, key, nonce);
    u8 *buffer = calloc(1, data_s);
    u8 *buffer2 = calloc(1, tag_s);

    if (ae && buffer)
    {
        memcpy(buffer, data, data_s);
        maid_aead_update(ae, ad, ad_s);
        maid_aead_update(ae2, ad, ad_s);

        maid_aead_crypt(ae, buffer, data_s, false);
        maid_aead_digest(ae, buffer2);

        ret = memcmp(buffer, cipher, data_s) == 0 &&
              memcmp(buffer2,   tag,  tag_s) == 0;

        maid_aead_crypt(ae2, buffer, data_s, true);
        maid_aead_digest(ae2, buffer2);

        ret = ret && memcmp(buffer, data, data_s) == 0 &&
                     memcmp(buffer2, tag,  tag_s) == 0;
    }

    maid_aead_del(ae);
    maid_aead_del(ae2);
    maid_mem_clear(buffer, data_s);
    maid_mem_clear(buffer2, tag_s);

    free(buffer);
    free(buffer2);

    return ret;
}

static bool
aes_gcm_vec1(void)
{
    u8 data[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
                 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
                 0xba, 0x63, 0x7b, 0x39};
    u8 ad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
               0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
               0xab, 0xad, 0xda, 0xd2};

    u8 key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    u8 nonce[12] = {0xca, 0xfe, 0xba, 0xbe,
                    0xfa, 0xce, 0xdb, 0xad,
                    0xde, 0xca, 0xf8, 0x88};

    u8 cipher[] = {0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
                   0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
                   0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
                   0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
                   0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
                   0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
                   0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
                   0xbc, 0xc9, 0xf6, 0x62};
    u8 tag[] = {0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
                0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b};

    u8 cipher2[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
                    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
                    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
                    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
                    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
                    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
                    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
                    0x3d, 0x58, 0xe0, 0x91};
    u8 tag2[] = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
                 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

    return aead_test(maid_aes_gcm_256, key, nonce,
                     ad, sizeof(ad), data, sizeof(data),
                     cipher, tag, sizeof(tag)) &&
           aead_test(maid_aes_gcm_128, key, nonce,
                     ad, sizeof(ad), data, sizeof(data),
                     cipher2, tag2, sizeof(tag2));
}

extern int
main(void)
{
    aes_tests();

    chacha_tests();
    poly1305_tests();
    chacha20poly1305_tests();

    return failures == 0 && aes_gcm_vec1() ?
           EXIT_SUCCESS : EXIT_FAILURE;
}
