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

#include <maid/block.h>
#include <maid/stream.h>
#include <maid/aead.h>

/* Thanks to AES NIST extensive tests, most of this file is machine-generated
 * Won't try to make it 80 columns wrapped, otherwise it will be massive */

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
fail_test(char *file, char *num, bool decrypt)
{
    fprintf(stderr, "- %s Test %s from %s Failed\n",
           (decrypt) ? "Decryption" : "Encryption", num, file);
    failures++;
}

/* AES NIST vectors */

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
            fail_test(file, num, decrypt);
    }
    maid_block_del(bl);

    maid_mem_clear(key,    sizeof(key));
    maid_mem_clear(input,  sizeof(input));
    maid_mem_clear(output, sizeof(output));
}

static void
aes_test_gfsbox_128(void)
{
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "0","00000000000000000000000000000000","f34481ec3cc627bacd5dc3fb08f273e6","0336763e966d92595a567cc9ce537f5e", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "1","00000000000000000000000000000000","9798c4640bad75c7c3227db910174e72","a9a1631bf4996954ebc093957b234589", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "2","00000000000000000000000000000000","96ab5c2ff612d9dfaae8c31f30c42168","ff4f8391a6a40ca5b25d23bedd44a597", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "3","00000000000000000000000000000000","6a118a874519e64e9963798a503f1d35","dc43be40be0e53712f7e2bf5ca707209", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "4","00000000000000000000000000000000","cb9fceec81286ca3e989bd979b0cb284","92beedab1895a94faa69b632e5cc47ce", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "5","00000000000000000000000000000000","b26aeb1874e47ca8358ff22378f09144","459264f4798f6a78bacb89c15ed3d601", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "6","00000000000000000000000000000000","58c8e00b2631686d54eab84b91f0aca1","08a4e2efec8a8e3312ca7460b9040bbf", false);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "0","00000000000000000000000000000000","0336763e966d92595a567cc9ce537f5e","f34481ec3cc627bacd5dc3fb08f273e6", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "1","00000000000000000000000000000000","a9a1631bf4996954ebc093957b234589","9798c4640bad75c7c3227db910174e72", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "2","00000000000000000000000000000000","ff4f8391a6a40ca5b25d23bedd44a597","96ab5c2ff612d9dfaae8c31f30c42168", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "3","00000000000000000000000000000000","dc43be40be0e53712f7e2bf5ca707209","6a118a874519e64e9963798a503f1d35", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "4","00000000000000000000000000000000","92beedab1895a94faa69b632e5cc47ce","cb9fceec81286ca3e989bd979b0cb284", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "5","00000000000000000000000000000000","459264f4798f6a78bacb89c15ed3d601","b26aeb1874e47ca8358ff22378f09144", true);
    aes_test(maid_aes_128, "ECBGFSbox128.rsp", "6","00000000000000000000000000000000","08a4e2efec8a8e3312ca7460b9040bbf","58c8e00b2631686d54eab84b91f0aca1", true);
}

static void
aes_test_keysbox_128(void)
{
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "0","10a58869d74be5a374cf867cfb473859","00000000000000000000000000000000","6d251e6944b051e04eaa6fb4dbf78465", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "1","caea65cdbb75e9169ecd22ebe6e54675","00000000000000000000000000000000","6e29201190152df4ee058139def610bb", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "2","a2e2fa9baf7d20822ca9f0542f764a41","00000000000000000000000000000000","c3b44b95d9d2f25670eee9a0de099fa3", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "3","b6364ac4e1de1e285eaf144a2415f7a0","00000000000000000000000000000000","5d9b05578fc944b3cf1ccf0e746cd581", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "4","64cf9c7abc50b888af65f49d521944b2","00000000000000000000000000000000","f7efc89d5dba578104016ce5ad659c05", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "5","47d6742eefcc0465dc96355e851b64d9","00000000000000000000000000000000","0306194f666d183624aa230a8b264ae7", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "6","3eb39790678c56bee34bbcdeccf6cdb5","00000000000000000000000000000000","858075d536d79ccee571f7d7204b1f67", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "7","64110a924f0743d500ccadae72c13427","00000000000000000000000000000000","35870c6a57e9e92314bcb8087cde72ce", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "8","18d8126516f8a12ab1a36d9f04d68e51","00000000000000000000000000000000","6c68e9be5ec41e22c825b7c7affb4363", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "9","f530357968578480b398a3c251cd1093","00000000000000000000000000000000","f5df39990fc688f1b07224cc03e86cea", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "10","da84367f325d42d601b4326964802e8e","00000000000000000000000000000000","bba071bcb470f8f6586e5d3add18bc66", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "11","e37b1c6aa2846f6fdb413f238b089f23","00000000000000000000000000000000","43c9f7e62f5d288bb27aa40ef8fe1ea8", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "12","6c002b682483e0cabcc731c253be5674","00000000000000000000000000000000","3580d19cff44f1014a7c966a69059de5", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "13","143ae8ed6555aba96110ab58893a8ae1","00000000000000000000000000000000","806da864dd29d48deafbe764f8202aef", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "14","b69418a85332240dc82492353956ae0c","00000000000000000000000000000000","a303d940ded8f0baff6f75414cac5243", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "15","71b5c08a1993e1362e4d0ce9b22b78d5","00000000000000000000000000000000","c2dabd117f8a3ecabfbb11d12194d9d0", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "16","e234cdca2606b81f29408d5f6da21206","00000000000000000000000000000000","fff60a4740086b3b9c56195b98d91a7b", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "17","13237c49074a3da078dc1d828bb78c6f","00000000000000000000000000000000","8146a08e2357f0caa30ca8c94d1a0544", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "18","3071a2a48fe6cbd04f1a129098e308f8","00000000000000000000000000000000","4b98e06d356deb07ebb824e5713f7be3", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "19","90f42ec0f68385f2ffc5dfc03a654dce","00000000000000000000000000000000","7a20a53d460fc9ce0423a7a0764c6cf2", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "20","febd9a24d8b65c1c787d50a4ed3619a9","00000000000000000000000000000000","f4a70d8af877f9b02b4c40df57d45b17", false);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "0","10a58869d74be5a374cf867cfb473859","6d251e6944b051e04eaa6fb4dbf78465","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "1","caea65cdbb75e9169ecd22ebe6e54675","6e29201190152df4ee058139def610bb","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "2","a2e2fa9baf7d20822ca9f0542f764a41","c3b44b95d9d2f25670eee9a0de099fa3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "3","b6364ac4e1de1e285eaf144a2415f7a0","5d9b05578fc944b3cf1ccf0e746cd581","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "4","64cf9c7abc50b888af65f49d521944b2","f7efc89d5dba578104016ce5ad659c05","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "5","47d6742eefcc0465dc96355e851b64d9","0306194f666d183624aa230a8b264ae7","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "6","3eb39790678c56bee34bbcdeccf6cdb5","858075d536d79ccee571f7d7204b1f67","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "7","64110a924f0743d500ccadae72c13427","35870c6a57e9e92314bcb8087cde72ce","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "8","18d8126516f8a12ab1a36d9f04d68e51","6c68e9be5ec41e22c825b7c7affb4363","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "9","f530357968578480b398a3c251cd1093","f5df39990fc688f1b07224cc03e86cea","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "10","da84367f325d42d601b4326964802e8e","bba071bcb470f8f6586e5d3add18bc66","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "11","e37b1c6aa2846f6fdb413f238b089f23","43c9f7e62f5d288bb27aa40ef8fe1ea8","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "12","6c002b682483e0cabcc731c253be5674","3580d19cff44f1014a7c966a69059de5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "13","143ae8ed6555aba96110ab58893a8ae1","806da864dd29d48deafbe764f8202aef","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "14","b69418a85332240dc82492353956ae0c","a303d940ded8f0baff6f75414cac5243","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "15","71b5c08a1993e1362e4d0ce9b22b78d5","c2dabd117f8a3ecabfbb11d12194d9d0","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "16","e234cdca2606b81f29408d5f6da21206","fff60a4740086b3b9c56195b98d91a7b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "17","13237c49074a3da078dc1d828bb78c6f","8146a08e2357f0caa30ca8c94d1a0544","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "18","3071a2a48fe6cbd04f1a129098e308f8","4b98e06d356deb07ebb824e5713f7be3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "19","90f42ec0f68385f2ffc5dfc03a654dce","7a20a53d460fc9ce0423a7a0764c6cf2","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBKeySbox128.rsp", "20","febd9a24d8b65c1c787d50a4ed3619a9","f4a70d8af877f9b02b4c40df57d45b17","00000000000000000000000000000000", true);
}

static void
aes_test_varkey_128(void)
{
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "0","80000000000000000000000000000000","00000000000000000000000000000000","0edd33d3c621e546455bd8ba1418bec8", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "1","c0000000000000000000000000000000","00000000000000000000000000000000","4bc3f883450c113c64ca42e1112a9e87", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "2","e0000000000000000000000000000000","00000000000000000000000000000000","72a1da770f5d7ac4c9ef94d822affd97", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "3","f0000000000000000000000000000000","00000000000000000000000000000000","970014d634e2b7650777e8e84d03ccd8", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "4","f8000000000000000000000000000000","00000000000000000000000000000000","f17e79aed0db7e279e955b5f493875a7", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "5","fc000000000000000000000000000000","00000000000000000000000000000000","9ed5a75136a940d0963da379db4af26a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "6","fe000000000000000000000000000000","00000000000000000000000000000000","c4295f83465c7755e8fa364bac6a7ea5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "7","ff000000000000000000000000000000","00000000000000000000000000000000","b1d758256b28fd850ad4944208cf1155", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "8","ff800000000000000000000000000000","00000000000000000000000000000000","42ffb34c743de4d88ca38011c990890b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "9","ffc00000000000000000000000000000","00000000000000000000000000000000","9958f0ecea8b2172c0c1995f9182c0f3", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "10","ffe00000000000000000000000000000","00000000000000000000000000000000","956d7798fac20f82a8823f984d06f7f5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "11","fff00000000000000000000000000000","00000000000000000000000000000000","a01bf44f2d16be928ca44aaf7b9b106b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "12","fff80000000000000000000000000000","00000000000000000000000000000000","b5f1a33e50d40d103764c76bd4c6b6f8", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "13","fffc0000000000000000000000000000","00000000000000000000000000000000","2637050c9fc0d4817e2d69de878aee8d", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "14","fffe0000000000000000000000000000","00000000000000000000000000000000","113ecbe4a453269a0dd26069467fb5b5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "15","ffff0000000000000000000000000000","00000000000000000000000000000000","97d0754fe68f11b9e375d070a608c884", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "16","ffff8000000000000000000000000000","00000000000000000000000000000000","c6a0b3e998d05068a5399778405200b4", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "17","ffffc000000000000000000000000000","00000000000000000000000000000000","df556a33438db87bc41b1752c55e5e49", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "18","ffffe000000000000000000000000000","00000000000000000000000000000000","90fb128d3a1af6e548521bb962bf1f05", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "19","fffff000000000000000000000000000","00000000000000000000000000000000","26298e9c1db517c215fadfb7d2a8d691", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "20","fffff800000000000000000000000000","00000000000000000000000000000000","a6cb761d61f8292d0df393a279ad0380", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "21","fffffc00000000000000000000000000","00000000000000000000000000000000","12acd89b13cd5f8726e34d44fd486108", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "22","fffffe00000000000000000000000000","00000000000000000000000000000000","95b1703fc57ba09fe0c3580febdd7ed4", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "23","ffffff00000000000000000000000000","00000000000000000000000000000000","de11722d893e9f9121c381becc1da59a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "24","ffffff80000000000000000000000000","00000000000000000000000000000000","6d114ccb27bf391012e8974c546d9bf2", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "25","ffffffc0000000000000000000000000","00000000000000000000000000000000","5ce37e17eb4646ecfac29b9cc38d9340", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "26","ffffffe0000000000000000000000000","00000000000000000000000000000000","18c1b6e2157122056d0243d8a165cddb", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "27","fffffff0000000000000000000000000","00000000000000000000000000000000","99693e6a59d1366c74d823562d7e1431", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "28","fffffff8000000000000000000000000","00000000000000000000000000000000","6c7c64dc84a8bba758ed17eb025a57e3", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "29","fffffffc000000000000000000000000","00000000000000000000000000000000","e17bc79f30eaab2fac2cbbe3458d687a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "30","fffffffe000000000000000000000000","00000000000000000000000000000000","1114bc2028009b923f0b01915ce5e7c4", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "31","ffffffff000000000000000000000000","00000000000000000000000000000000","9c28524a16a1e1c1452971caa8d13476", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "32","ffffffff800000000000000000000000","00000000000000000000000000000000","ed62e16363638360fdd6ad62112794f0", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "33","ffffffffc00000000000000000000000","00000000000000000000000000000000","5a8688f0b2a2c16224c161658ffd4044", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "34","ffffffffe00000000000000000000000","00000000000000000000000000000000","23f710842b9bb9c32f26648c786807ca", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "35","fffffffff00000000000000000000000","00000000000000000000000000000000","44a98bf11e163f632c47ec6a49683a89", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "36","fffffffff80000000000000000000000","00000000000000000000000000000000","0f18aff94274696d9b61848bd50ac5e5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "37","fffffffffc0000000000000000000000","00000000000000000000000000000000","82408571c3e2424540207f833b6dda69", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "38","fffffffffe0000000000000000000000","00000000000000000000000000000000","303ff996947f0c7d1f43c8f3027b9b75", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "39","ffffffffff0000000000000000000000","00000000000000000000000000000000","7df4daf4ad29a3615a9b6ece5c99518a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "40","ffffffffff8000000000000000000000","00000000000000000000000000000000","c72954a48d0774db0b4971c526260415", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "41","ffffffffffc000000000000000000000","00000000000000000000000000000000","1df9b76112dc6531e07d2cfda04411f0", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "42","ffffffffffe000000000000000000000","00000000000000000000000000000000","8e4d8e699119e1fc87545a647fb1d34f", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "43","fffffffffff000000000000000000000","00000000000000000000000000000000","e6c4807ae11f36f091c57d9fb68548d1", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "44","fffffffffff800000000000000000000","00000000000000000000000000000000","8ebf73aad49c82007f77a5c1ccec6ab4", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "45","fffffffffffc00000000000000000000","00000000000000000000000000000000","4fb288cc2040049001d2c7585ad123fc", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "46","fffffffffffe00000000000000000000","00000000000000000000000000000000","04497110efb9dceb13e2b13fb4465564", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "47","ffffffffffff00000000000000000000","00000000000000000000000000000000","75550e6cb5a88e49634c9ab69eda0430", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "48","ffffffffffff80000000000000000000","00000000000000000000000000000000","b6768473ce9843ea66a81405dd50b345", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "49","ffffffffffffc0000000000000000000","00000000000000000000000000000000","cb2f430383f9084e03a653571e065de6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "50","ffffffffffffe0000000000000000000","00000000000000000000000000000000","ff4e66c07bae3e79fb7d210847a3b0ba", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "51","fffffffffffff0000000000000000000","00000000000000000000000000000000","7b90785125505fad59b13c186dd66ce3", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "52","fffffffffffff8000000000000000000","00000000000000000000000000000000","8b527a6aebdaec9eaef8eda2cb7783e5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "53","fffffffffffffc000000000000000000","00000000000000000000000000000000","43fdaf53ebbc9880c228617d6a9b548b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "54","fffffffffffffe000000000000000000","00000000000000000000000000000000","53786104b9744b98f052c46f1c850d0b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "55","ffffffffffffff000000000000000000","00000000000000000000000000000000","b5ab3013dd1e61df06cbaf34ca2aee78", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "56","ffffffffffffff800000000000000000","00000000000000000000000000000000","7470469be9723030fdcc73a8cd4fbb10", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "57","ffffffffffffffc00000000000000000","00000000000000000000000000000000","a35a63f5343ebe9ef8167bcb48ad122e", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "58","ffffffffffffffe00000000000000000","00000000000000000000000000000000","fd8687f0757a210e9fdf181204c30863", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "59","fffffffffffffff00000000000000000","00000000000000000000000000000000","7a181e84bd5457d26a88fbae96018fb0", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "60","fffffffffffffff80000000000000000","00000000000000000000000000000000","653317b9362b6f9b9e1a580e68d494b5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "61","fffffffffffffffc0000000000000000","00000000000000000000000000000000","995c9dc0b689f03c45867b5faa5c18d1", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "62","fffffffffffffffe0000000000000000","00000000000000000000000000000000","77a4d96d56dda398b9aabecfc75729fd", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "63","ffffffffffffffff0000000000000000","00000000000000000000000000000000","84be19e053635f09f2665e7bae85b42d", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "64","ffffffffffffffff8000000000000000","00000000000000000000000000000000","32cd652842926aea4aa6137bb2be2b5e", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "65","ffffffffffffffffc000000000000000","00000000000000000000000000000000","493d4a4f38ebb337d10aa84e9171a554", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "66","ffffffffffffffffe000000000000000","00000000000000000000000000000000","d9bff7ff454b0ec5a4a2a69566e2cb84", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "67","fffffffffffffffff000000000000000","00000000000000000000000000000000","3535d565ace3f31eb249ba2cc6765d7a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "68","fffffffffffffffff800000000000000","00000000000000000000000000000000","f60e91fc3269eecf3231c6e9945697c6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "69","fffffffffffffffffc00000000000000","00000000000000000000000000000000","ab69cfadf51f8e604d9cc37182f6635a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "70","fffffffffffffffffe00000000000000","00000000000000000000000000000000","7866373f24a0b6ed56e0d96fcdafb877", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "71","ffffffffffffffffff00000000000000","00000000000000000000000000000000","1ea448c2aac954f5d812e9d78494446a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "72","ffffffffffffffffff80000000000000","00000000000000000000000000000000","acc5599dd8ac02239a0fef4a36dd1668", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "73","ffffffffffffffffffc0000000000000","00000000000000000000000000000000","d8764468bb103828cf7e1473ce895073", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "74","ffffffffffffffffffe0000000000000","00000000000000000000000000000000","1b0d02893683b9f180458e4aa6b73982", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "75","fffffffffffffffffff0000000000000","00000000000000000000000000000000","96d9b017d302df410a937dcdb8bb6e43", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "76","fffffffffffffffffff8000000000000","00000000000000000000000000000000","ef1623cc44313cff440b1594a7e21cc6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "77","fffffffffffffffffffc000000000000","00000000000000000000000000000000","284ca2fa35807b8b0ae4d19e11d7dbd7", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "78","fffffffffffffffffffe000000000000","00000000000000000000000000000000","f2e976875755f9401d54f36e2a23a594", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "79","ffffffffffffffffffff000000000000","00000000000000000000000000000000","ec198a18e10e532403b7e20887c8dd80", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "80","ffffffffffffffffffff800000000000","00000000000000000000000000000000","545d50ebd919e4a6949d96ad47e46a80", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "81","ffffffffffffffffffffc00000000000","00000000000000000000000000000000","dbdfb527060e0a71009c7bb0c68f1d44", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "82","ffffffffffffffffffffe00000000000","00000000000000000000000000000000","9cfa1322ea33da2173a024f2ff0d896d", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "83","fffffffffffffffffffff00000000000","00000000000000000000000000000000","8785b1a75b0f3bd958dcd0e29318c521", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "84","fffffffffffffffffffff80000000000","00000000000000000000000000000000","38f67b9e98e4a97b6df030a9fcdd0104", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "85","fffffffffffffffffffffc0000000000","00000000000000000000000000000000","192afffb2c880e82b05926d0fc6c448b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "86","fffffffffffffffffffffe0000000000","00000000000000000000000000000000","6a7980ce7b105cf530952d74daaf798c", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "87","ffffffffffffffffffffff0000000000","00000000000000000000000000000000","ea3695e1351b9d6858bd958cf513ef6c", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "88","ffffffffffffffffffffff8000000000","00000000000000000000000000000000","6da0490ba0ba0343b935681d2cce5ba1", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "89","ffffffffffffffffffffffc000000000","00000000000000000000000000000000","f0ea23af08534011c60009ab29ada2f1", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "90","ffffffffffffffffffffffe000000000","00000000000000000000000000000000","ff13806cf19cc38721554d7c0fcdcd4b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "91","fffffffffffffffffffffff000000000","00000000000000000000000000000000","6838af1f4f69bae9d85dd188dcdf0688", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "92","fffffffffffffffffffffff800000000","00000000000000000000000000000000","36cf44c92d550bfb1ed28ef583ddf5d7", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "93","fffffffffffffffffffffffc00000000","00000000000000000000000000000000","d06e3195b5376f109d5c4ec6c5d62ced", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "94","fffffffffffffffffffffffe00000000","00000000000000000000000000000000","c440de014d3d610707279b13242a5c36", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "95","ffffffffffffffffffffffff00000000","00000000000000000000000000000000","f0c5c6ffa5e0bd3a94c88f6b6f7c16b9", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "96","ffffffffffffffffffffffff80000000","00000000000000000000000000000000","3e40c3901cd7effc22bffc35dee0b4d9", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "97","ffffffffffffffffffffffffc0000000","00000000000000000000000000000000","b63305c72bedfab97382c406d0c49bc6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "98","ffffffffffffffffffffffffe0000000","00000000000000000000000000000000","36bbaab22a6bd4925a99a2b408d2dbae", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "99","fffffffffffffffffffffffff0000000","00000000000000000000000000000000","307c5b8fcd0533ab98bc51e27a6ce461", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "100","fffffffffffffffffffffffff8000000","00000000000000000000000000000000","829c04ff4c07513c0b3ef05c03e337b5", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "101","fffffffffffffffffffffffffc000000","00000000000000000000000000000000","f17af0e895dda5eb98efc68066e84c54", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "102","fffffffffffffffffffffffffe000000","00000000000000000000000000000000","277167f3812afff1ffacb4a934379fc3", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "103","ffffffffffffffffffffffffff000000","00000000000000000000000000000000","2cb1dc3a9c72972e425ae2ef3eb597cd", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "104","ffffffffffffffffffffffffff800000","00000000000000000000000000000000","36aeaa3a213e968d4b5b679d3a2c97fe", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "105","ffffffffffffffffffffffffffc00000","00000000000000000000000000000000","9241daca4fdd034a82372db50e1a0f3f", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "106","ffffffffffffffffffffffffffe00000","00000000000000000000000000000000","c14574d9cd00cf2b5a7f77e53cd57885", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "107","fffffffffffffffffffffffffff00000","00000000000000000000000000000000","793de39236570aba83ab9b737cb521c9", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "108","fffffffffffffffffffffffffff80000","00000000000000000000000000000000","16591c0f27d60e29b85a96c33861a7ef", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "109","fffffffffffffffffffffffffffc0000","00000000000000000000000000000000","44fb5c4d4f5cb79be5c174a3b1c97348", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "110","fffffffffffffffffffffffffffe0000","00000000000000000000000000000000","674d2b61633d162be59dde04222f4740", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "111","ffffffffffffffffffffffffffff0000","00000000000000000000000000000000","b4750ff263a65e1f9e924ccfd98f3e37", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "112","ffffffffffffffffffffffffffff8000","00000000000000000000000000000000","62d0662d6eaeddedebae7f7ea3a4f6b6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "113","ffffffffffffffffffffffffffffc000","00000000000000000000000000000000","70c46bb30692be657f7eaa93ebad9897", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "114","ffffffffffffffffffffffffffffe000","00000000000000000000000000000000","323994cfb9da285a5d9642e1759b224a", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "115","fffffffffffffffffffffffffffff000","00000000000000000000000000000000","1dbf57877b7b17385c85d0b54851e371", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "116","fffffffffffffffffffffffffffff800","00000000000000000000000000000000","dfa5c097cdc1532ac071d57b1d28d1bd", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "117","fffffffffffffffffffffffffffffc00","00000000000000000000000000000000","3a0c53fa37311fc10bd2a9981f513174", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "118","fffffffffffffffffffffffffffffe00","00000000000000000000000000000000","ba4f970c0a25c41814bdae2e506be3b4", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "119","ffffffffffffffffffffffffffffff00","00000000000000000000000000000000","2dce3acb727cd13ccd76d425ea56e4f6", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "120","ffffffffffffffffffffffffffffff80","00000000000000000000000000000000","5160474d504b9b3eefb68d35f245f4b3", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "121","ffffffffffffffffffffffffffffffc0","00000000000000000000000000000000","41a8a947766635dec37553d9a6c0cbb7", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "122","ffffffffffffffffffffffffffffffe0","00000000000000000000000000000000","25d6cfe6881f2bf497dd14cd4ddf445b", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "123","fffffffffffffffffffffffffffffff0","00000000000000000000000000000000","41c78c135ed9e98c096640647265da1e", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "124","fffffffffffffffffffffffffffffff8","00000000000000000000000000000000","5a4d404d8917e353e92a21072c3b2305", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "125","fffffffffffffffffffffffffffffffc","00000000000000000000000000000000","02bc96846b3fdc71643f384cd3cc3eaf", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "126","fffffffffffffffffffffffffffffffe","00000000000000000000000000000000","9ba4a9143f4e5d4048521c4f8877d88e", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "127","ffffffffffffffffffffffffffffffff","00000000000000000000000000000000","a1f6258c877d5fcd8964484538bfc92c", false);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "0","80000000000000000000000000000000","0edd33d3c621e546455bd8ba1418bec8","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "1","c0000000000000000000000000000000","4bc3f883450c113c64ca42e1112a9e87","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "2","e0000000000000000000000000000000","72a1da770f5d7ac4c9ef94d822affd97","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "3","f0000000000000000000000000000000","970014d634e2b7650777e8e84d03ccd8","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "4","f8000000000000000000000000000000","f17e79aed0db7e279e955b5f493875a7","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "5","fc000000000000000000000000000000","9ed5a75136a940d0963da379db4af26a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "6","fe000000000000000000000000000000","c4295f83465c7755e8fa364bac6a7ea5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "7","ff000000000000000000000000000000","b1d758256b28fd850ad4944208cf1155","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "8","ff800000000000000000000000000000","42ffb34c743de4d88ca38011c990890b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "9","ffc00000000000000000000000000000","9958f0ecea8b2172c0c1995f9182c0f3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "10","ffe00000000000000000000000000000","956d7798fac20f82a8823f984d06f7f5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "11","fff00000000000000000000000000000","a01bf44f2d16be928ca44aaf7b9b106b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "12","fff80000000000000000000000000000","b5f1a33e50d40d103764c76bd4c6b6f8","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "13","fffc0000000000000000000000000000","2637050c9fc0d4817e2d69de878aee8d","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "14","fffe0000000000000000000000000000","113ecbe4a453269a0dd26069467fb5b5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "15","ffff0000000000000000000000000000","97d0754fe68f11b9e375d070a608c884","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "16","ffff8000000000000000000000000000","c6a0b3e998d05068a5399778405200b4","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "17","ffffc000000000000000000000000000","df556a33438db87bc41b1752c55e5e49","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "18","ffffe000000000000000000000000000","90fb128d3a1af6e548521bb962bf1f05","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "19","fffff000000000000000000000000000","26298e9c1db517c215fadfb7d2a8d691","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "20","fffff800000000000000000000000000","a6cb761d61f8292d0df393a279ad0380","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "21","fffffc00000000000000000000000000","12acd89b13cd5f8726e34d44fd486108","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "22","fffffe00000000000000000000000000","95b1703fc57ba09fe0c3580febdd7ed4","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "23","ffffff00000000000000000000000000","de11722d893e9f9121c381becc1da59a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "24","ffffff80000000000000000000000000","6d114ccb27bf391012e8974c546d9bf2","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "25","ffffffc0000000000000000000000000","5ce37e17eb4646ecfac29b9cc38d9340","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "26","ffffffe0000000000000000000000000","18c1b6e2157122056d0243d8a165cddb","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "27","fffffff0000000000000000000000000","99693e6a59d1366c74d823562d7e1431","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "28","fffffff8000000000000000000000000","6c7c64dc84a8bba758ed17eb025a57e3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "29","fffffffc000000000000000000000000","e17bc79f30eaab2fac2cbbe3458d687a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "30","fffffffe000000000000000000000000","1114bc2028009b923f0b01915ce5e7c4","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "31","ffffffff000000000000000000000000","9c28524a16a1e1c1452971caa8d13476","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "32","ffffffff800000000000000000000000","ed62e16363638360fdd6ad62112794f0","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "33","ffffffffc00000000000000000000000","5a8688f0b2a2c16224c161658ffd4044","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "34","ffffffffe00000000000000000000000","23f710842b9bb9c32f26648c786807ca","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "35","fffffffff00000000000000000000000","44a98bf11e163f632c47ec6a49683a89","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "36","fffffffff80000000000000000000000","0f18aff94274696d9b61848bd50ac5e5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "37","fffffffffc0000000000000000000000","82408571c3e2424540207f833b6dda69","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "38","fffffffffe0000000000000000000000","303ff996947f0c7d1f43c8f3027b9b75","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "39","ffffffffff0000000000000000000000","7df4daf4ad29a3615a9b6ece5c99518a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "40","ffffffffff8000000000000000000000","c72954a48d0774db0b4971c526260415","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "41","ffffffffffc000000000000000000000","1df9b76112dc6531e07d2cfda04411f0","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "42","ffffffffffe000000000000000000000","8e4d8e699119e1fc87545a647fb1d34f","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "43","fffffffffff000000000000000000000","e6c4807ae11f36f091c57d9fb68548d1","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "44","fffffffffff800000000000000000000","8ebf73aad49c82007f77a5c1ccec6ab4","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "45","fffffffffffc00000000000000000000","4fb288cc2040049001d2c7585ad123fc","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "46","fffffffffffe00000000000000000000","04497110efb9dceb13e2b13fb4465564","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "47","ffffffffffff00000000000000000000","75550e6cb5a88e49634c9ab69eda0430","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "48","ffffffffffff80000000000000000000","b6768473ce9843ea66a81405dd50b345","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "49","ffffffffffffc0000000000000000000","cb2f430383f9084e03a653571e065de6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "50","ffffffffffffe0000000000000000000","ff4e66c07bae3e79fb7d210847a3b0ba","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "51","fffffffffffff0000000000000000000","7b90785125505fad59b13c186dd66ce3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "52","fffffffffffff8000000000000000000","8b527a6aebdaec9eaef8eda2cb7783e5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "53","fffffffffffffc000000000000000000","43fdaf53ebbc9880c228617d6a9b548b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "54","fffffffffffffe000000000000000000","53786104b9744b98f052c46f1c850d0b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "55","ffffffffffffff000000000000000000","b5ab3013dd1e61df06cbaf34ca2aee78","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "56","ffffffffffffff800000000000000000","7470469be9723030fdcc73a8cd4fbb10","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "57","ffffffffffffffc00000000000000000","a35a63f5343ebe9ef8167bcb48ad122e","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "58","ffffffffffffffe00000000000000000","fd8687f0757a210e9fdf181204c30863","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "59","fffffffffffffff00000000000000000","7a181e84bd5457d26a88fbae96018fb0","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "60","fffffffffffffff80000000000000000","653317b9362b6f9b9e1a580e68d494b5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "61","fffffffffffffffc0000000000000000","995c9dc0b689f03c45867b5faa5c18d1","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "62","fffffffffffffffe0000000000000000","77a4d96d56dda398b9aabecfc75729fd","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "63","ffffffffffffffff0000000000000000","84be19e053635f09f2665e7bae85b42d","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "64","ffffffffffffffff8000000000000000","32cd652842926aea4aa6137bb2be2b5e","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "65","ffffffffffffffffc000000000000000","493d4a4f38ebb337d10aa84e9171a554","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "66","ffffffffffffffffe000000000000000","d9bff7ff454b0ec5a4a2a69566e2cb84","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "67","fffffffffffffffff000000000000000","3535d565ace3f31eb249ba2cc6765d7a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "68","fffffffffffffffff800000000000000","f60e91fc3269eecf3231c6e9945697c6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "69","fffffffffffffffffc00000000000000","ab69cfadf51f8e604d9cc37182f6635a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "70","fffffffffffffffffe00000000000000","7866373f24a0b6ed56e0d96fcdafb877","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "71","ffffffffffffffffff00000000000000","1ea448c2aac954f5d812e9d78494446a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "72","ffffffffffffffffff80000000000000","acc5599dd8ac02239a0fef4a36dd1668","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "73","ffffffffffffffffffc0000000000000","d8764468bb103828cf7e1473ce895073","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "74","ffffffffffffffffffe0000000000000","1b0d02893683b9f180458e4aa6b73982","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "75","fffffffffffffffffff0000000000000","96d9b017d302df410a937dcdb8bb6e43","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "76","fffffffffffffffffff8000000000000","ef1623cc44313cff440b1594a7e21cc6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "77","fffffffffffffffffffc000000000000","284ca2fa35807b8b0ae4d19e11d7dbd7","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "78","fffffffffffffffffffe000000000000","f2e976875755f9401d54f36e2a23a594","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "79","ffffffffffffffffffff000000000000","ec198a18e10e532403b7e20887c8dd80","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "80","ffffffffffffffffffff800000000000","545d50ebd919e4a6949d96ad47e46a80","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "81","ffffffffffffffffffffc00000000000","dbdfb527060e0a71009c7bb0c68f1d44","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "82","ffffffffffffffffffffe00000000000","9cfa1322ea33da2173a024f2ff0d896d","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "83","fffffffffffffffffffff00000000000","8785b1a75b0f3bd958dcd0e29318c521","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "84","fffffffffffffffffffff80000000000","38f67b9e98e4a97b6df030a9fcdd0104","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "85","fffffffffffffffffffffc0000000000","192afffb2c880e82b05926d0fc6c448b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "86","fffffffffffffffffffffe0000000000","6a7980ce7b105cf530952d74daaf798c","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "87","ffffffffffffffffffffff0000000000","ea3695e1351b9d6858bd958cf513ef6c","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "88","ffffffffffffffffffffff8000000000","6da0490ba0ba0343b935681d2cce5ba1","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "89","ffffffffffffffffffffffc000000000","f0ea23af08534011c60009ab29ada2f1","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "90","ffffffffffffffffffffffe000000000","ff13806cf19cc38721554d7c0fcdcd4b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "91","fffffffffffffffffffffff000000000","6838af1f4f69bae9d85dd188dcdf0688","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "92","fffffffffffffffffffffff800000000","36cf44c92d550bfb1ed28ef583ddf5d7","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "93","fffffffffffffffffffffffc00000000","d06e3195b5376f109d5c4ec6c5d62ced","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "94","fffffffffffffffffffffffe00000000","c440de014d3d610707279b13242a5c36","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "95","ffffffffffffffffffffffff00000000","f0c5c6ffa5e0bd3a94c88f6b6f7c16b9","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "96","ffffffffffffffffffffffff80000000","3e40c3901cd7effc22bffc35dee0b4d9","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "97","ffffffffffffffffffffffffc0000000","b63305c72bedfab97382c406d0c49bc6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "98","ffffffffffffffffffffffffe0000000","36bbaab22a6bd4925a99a2b408d2dbae","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "99","fffffffffffffffffffffffff0000000","307c5b8fcd0533ab98bc51e27a6ce461","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "100","fffffffffffffffffffffffff8000000","829c04ff4c07513c0b3ef05c03e337b5","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "101","fffffffffffffffffffffffffc000000","f17af0e895dda5eb98efc68066e84c54","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "102","fffffffffffffffffffffffffe000000","277167f3812afff1ffacb4a934379fc3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "103","ffffffffffffffffffffffffff000000","2cb1dc3a9c72972e425ae2ef3eb597cd","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "104","ffffffffffffffffffffffffff800000","36aeaa3a213e968d4b5b679d3a2c97fe","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "105","ffffffffffffffffffffffffffc00000","9241daca4fdd034a82372db50e1a0f3f","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "106","ffffffffffffffffffffffffffe00000","c14574d9cd00cf2b5a7f77e53cd57885","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "107","fffffffffffffffffffffffffff00000","793de39236570aba83ab9b737cb521c9","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "108","fffffffffffffffffffffffffff80000","16591c0f27d60e29b85a96c33861a7ef","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "109","fffffffffffffffffffffffffffc0000","44fb5c4d4f5cb79be5c174a3b1c97348","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "110","fffffffffffffffffffffffffffe0000","674d2b61633d162be59dde04222f4740","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "111","ffffffffffffffffffffffffffff0000","b4750ff263a65e1f9e924ccfd98f3e37","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "112","ffffffffffffffffffffffffffff8000","62d0662d6eaeddedebae7f7ea3a4f6b6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "113","ffffffffffffffffffffffffffffc000","70c46bb30692be657f7eaa93ebad9897","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "114","ffffffffffffffffffffffffffffe000","323994cfb9da285a5d9642e1759b224a","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "115","fffffffffffffffffffffffffffff000","1dbf57877b7b17385c85d0b54851e371","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "116","fffffffffffffffffffffffffffff800","dfa5c097cdc1532ac071d57b1d28d1bd","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "117","fffffffffffffffffffffffffffffc00","3a0c53fa37311fc10bd2a9981f513174","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "118","fffffffffffffffffffffffffffffe00","ba4f970c0a25c41814bdae2e506be3b4","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "119","ffffffffffffffffffffffffffffff00","2dce3acb727cd13ccd76d425ea56e4f6","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "120","ffffffffffffffffffffffffffffff80","5160474d504b9b3eefb68d35f245f4b3","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "121","ffffffffffffffffffffffffffffffc0","41a8a947766635dec37553d9a6c0cbb7","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "122","ffffffffffffffffffffffffffffffe0","25d6cfe6881f2bf497dd14cd4ddf445b","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "123","fffffffffffffffffffffffffffffff0","41c78c135ed9e98c096640647265da1e","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "124","fffffffffffffffffffffffffffffff8","5a4d404d8917e353e92a21072c3b2305","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "125","fffffffffffffffffffffffffffffffc","02bc96846b3fdc71643f384cd3cc3eaf","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "126","fffffffffffffffffffffffffffffffe","9ba4a9143f4e5d4048521c4f8877d88e","00000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarKey128.rsp", "127","ffffffffffffffffffffffffffffffff","a1f6258c877d5fcd8964484538bfc92c","00000000000000000000000000000000", true);
}

static void
aes_test_vartxt_128(void)
{
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "0","00000000000000000000000000000000","80000000000000000000000000000000","3ad78e726c1ec02b7ebfe92b23d9ec34", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "1","00000000000000000000000000000000","c0000000000000000000000000000000","aae5939c8efdf2f04e60b9fe7117b2c2", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "2","00000000000000000000000000000000","e0000000000000000000000000000000","f031d4d74f5dcbf39daaf8ca3af6e527", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "3","00000000000000000000000000000000","f0000000000000000000000000000000","96d9fd5cc4f07441727df0f33e401a36", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "4","00000000000000000000000000000000","f8000000000000000000000000000000","30ccdb044646d7e1f3ccea3dca08b8c0", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "5","00000000000000000000000000000000","fc000000000000000000000000000000","16ae4ce5042a67ee8e177b7c587ecc82", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "6","00000000000000000000000000000000","fe000000000000000000000000000000","b6da0bb11a23855d9c5cb1b4c6412e0a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "7","00000000000000000000000000000000","ff000000000000000000000000000000","db4f1aa530967d6732ce4715eb0ee24b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "8","00000000000000000000000000000000","ff800000000000000000000000000000","a81738252621dd180a34f3455b4baa2f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "9","00000000000000000000000000000000","ffc00000000000000000000000000000","77e2b508db7fd89234caf7939ee5621a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "10","00000000000000000000000000000000","ffe00000000000000000000000000000","b8499c251f8442ee13f0933b688fcd19", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "11","00000000000000000000000000000000","fff00000000000000000000000000000","965135f8a81f25c9d630b17502f68e53", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "12","00000000000000000000000000000000","fff80000000000000000000000000000","8b87145a01ad1c6cede995ea3670454f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "13","00000000000000000000000000000000","fffc0000000000000000000000000000","8eae3b10a0c8ca6d1d3b0fa61e56b0b2", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "14","00000000000000000000000000000000","fffe0000000000000000000000000000","64b4d629810fda6bafdf08f3b0d8d2c5", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "15","00000000000000000000000000000000","ffff0000000000000000000000000000","d7e5dbd3324595f8fdc7d7c571da6c2a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "16","00000000000000000000000000000000","ffff8000000000000000000000000000","f3f72375264e167fca9de2c1527d9606", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "17","00000000000000000000000000000000","ffffc000000000000000000000000000","8ee79dd4f401ff9b7ea945d86666c13b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "18","00000000000000000000000000000000","ffffe000000000000000000000000000","dd35cea2799940b40db3f819cb94c08b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "19","00000000000000000000000000000000","fffff000000000000000000000000000","6941cb6b3e08c2b7afa581ebdd607b87", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "20","00000000000000000000000000000000","fffff800000000000000000000000000","2c20f439f6bb097b29b8bd6d99aad799", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "21","00000000000000000000000000000000","fffffc00000000000000000000000000","625d01f058e565f77ae86378bd2c49b3", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "22","00000000000000000000000000000000","fffffe00000000000000000000000000","c0b5fd98190ef45fbb4301438d095950", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "23","00000000000000000000000000000000","ffffff00000000000000000000000000","13001ff5d99806efd25da34f56be854b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "24","00000000000000000000000000000000","ffffff80000000000000000000000000","3b594c60f5c8277a5113677f94208d82", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "25","00000000000000000000000000000000","ffffffc0000000000000000000000000","e9c0fc1818e4aa46bd2e39d638f89e05", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "26","00000000000000000000000000000000","ffffffe0000000000000000000000000","f8023ee9c3fdc45a019b4e985c7e1a54", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "27","00000000000000000000000000000000","fffffff0000000000000000000000000","35f40182ab4662f3023baec1ee796b57", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "28","00000000000000000000000000000000","fffffff8000000000000000000000000","3aebbad7303649b4194a6945c6cc3694", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "29","00000000000000000000000000000000","fffffffc000000000000000000000000","a2124bea53ec2834279bed7f7eb0f938", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "30","00000000000000000000000000000000","fffffffe000000000000000000000000","b9fb4399fa4facc7309e14ec98360b0a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "31","00000000000000000000000000000000","ffffffff000000000000000000000000","c26277437420c5d634f715aea81a9132", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "32","00000000000000000000000000000000","ffffffff800000000000000000000000","171a0e1b2dd424f0e089af2c4c10f32f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "33","00000000000000000000000000000000","ffffffffc00000000000000000000000","7cadbe402d1b208fe735edce00aee7ce", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "34","00000000000000000000000000000000","ffffffffe00000000000000000000000","43b02ff929a1485af6f5c6d6558baa0f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "35","00000000000000000000000000000000","fffffffff00000000000000000000000","092faacc9bf43508bf8fa8613ca75dea", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "36","00000000000000000000000000000000","fffffffff80000000000000000000000","cb2bf8280f3f9742c7ed513fe802629c", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "37","00000000000000000000000000000000","fffffffffc0000000000000000000000","215a41ee442fa992a6e323986ded3f68", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "38","00000000000000000000000000000000","fffffffffe0000000000000000000000","f21e99cf4f0f77cea836e11a2fe75fb1", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "39","00000000000000000000000000000000","ffffffffff0000000000000000000000","95e3a0ca9079e646331df8b4e70d2cd6", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "40","00000000000000000000000000000000","ffffffffff8000000000000000000000","4afe7f120ce7613f74fc12a01a828073", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "41","00000000000000000000000000000000","ffffffffffc000000000000000000000","827f000e75e2c8b9d479beed913fe678", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "42","00000000000000000000000000000000","ffffffffffe000000000000000000000","35830c8e7aaefe2d30310ef381cbf691", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "43","00000000000000000000000000000000","fffffffffff000000000000000000000","191aa0f2c8570144f38657ea4085ebe5", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "44","00000000000000000000000000000000","fffffffffff800000000000000000000","85062c2c909f15d9269b6c18ce99c4f0", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "45","00000000000000000000000000000000","fffffffffffc00000000000000000000","678034dc9e41b5a560ed239eeab1bc78", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "46","00000000000000000000000000000000","fffffffffffe00000000000000000000","c2f93a4ce5ab6d5d56f1b93cf19911c1", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "47","00000000000000000000000000000000","ffffffffffff00000000000000000000","1c3112bcb0c1dcc749d799743691bf82", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "48","00000000000000000000000000000000","ffffffffffff80000000000000000000","00c55bd75c7f9c881989d3ec1911c0d4", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "49","00000000000000000000000000000000","ffffffffffffc0000000000000000000","ea2e6b5ef182b7dff3629abd6a12045f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "50","00000000000000000000000000000000","ffffffffffffe0000000000000000000","22322327e01780b17397f24087f8cc6f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "51","00000000000000000000000000000000","fffffffffffff0000000000000000000","c9cacb5cd11692c373b2411768149ee7", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "52","00000000000000000000000000000000","fffffffffffff8000000000000000000","a18e3dbbca577860dab6b80da3139256", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "53","00000000000000000000000000000000","fffffffffffffc000000000000000000","79b61c37bf328ecca8d743265a3d425c", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "54","00000000000000000000000000000000","fffffffffffffe000000000000000000","d2d99c6bcc1f06fda8e27e8ae3f1ccc7", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "55","00000000000000000000000000000000","ffffffffffffff000000000000000000","1bfd4b91c701fd6b61b7f997829d663b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "56","00000000000000000000000000000000","ffffffffffffff800000000000000000","11005d52f25f16bdc9545a876a63490a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "57","00000000000000000000000000000000","ffffffffffffffc00000000000000000","3a4d354f02bb5a5e47d39666867f246a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "58","00000000000000000000000000000000","ffffffffffffffe00000000000000000","d451b8d6e1e1a0ebb155fbbf6e7b7dc3", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "59","00000000000000000000000000000000","fffffffffffffff00000000000000000","6898d4f42fa7ba6a10ac05e87b9f2080", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "60","00000000000000000000000000000000","fffffffffffffff80000000000000000","b611295e739ca7d9b50f8e4c0e754a3f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "61","00000000000000000000000000000000","fffffffffffffffc0000000000000000","7d33fc7d8abe3ca1936759f8f5deaf20", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "62","00000000000000000000000000000000","fffffffffffffffe0000000000000000","3b5e0f566dc96c298f0c12637539b25c", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "63","00000000000000000000000000000000","ffffffffffffffff0000000000000000","f807c3e7985fe0f5a50e2cdb25c5109e", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "64","00000000000000000000000000000000","ffffffffffffffff8000000000000000","41f992a856fb278b389a62f5d274d7e9", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "65","00000000000000000000000000000000","ffffffffffffffffc000000000000000","10d3ed7a6fe15ab4d91acbc7d0767ab1", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "66","00000000000000000000000000000000","ffffffffffffffffe000000000000000","21feecd45b2e675973ac33bf0c5424fc", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "67","00000000000000000000000000000000","fffffffffffffffff000000000000000","1480cb3955ba62d09eea668f7c708817", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "68","00000000000000000000000000000000","fffffffffffffffff800000000000000","66404033d6b72b609354d5496e7eb511", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "69","00000000000000000000000000000000","fffffffffffffffffc00000000000000","1c317a220a7d700da2b1e075b00266e1", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "70","00000000000000000000000000000000","fffffffffffffffffe00000000000000","ab3b89542233f1271bf8fd0c0f403545", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "71","00000000000000000000000000000000","ffffffffffffffffff00000000000000","d93eae966fac46dca927d6b114fa3f9e", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "72","00000000000000000000000000000000","ffffffffffffffffff80000000000000","1bdec521316503d9d5ee65df3ea94ddf", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "73","00000000000000000000000000000000","ffffffffffffffffffc0000000000000","eef456431dea8b4acf83bdae3717f75f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "74","00000000000000000000000000000000","ffffffffffffffffffe0000000000000","06f2519a2fafaa596bfef5cfa15c21b9", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "75","00000000000000000000000000000000","fffffffffffffffffff0000000000000","251a7eac7e2fe809e4aa8d0d7012531a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "76","00000000000000000000000000000000","fffffffffffffffffff8000000000000","3bffc16e4c49b268a20f8d96a60b4058", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "77","00000000000000000000000000000000","fffffffffffffffffffc000000000000","e886f9281999c5bb3b3e8862e2f7c988", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "78","00000000000000000000000000000000","fffffffffffffffffffe000000000000","563bf90d61beef39f48dd625fcef1361", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "79","00000000000000000000000000000000","ffffffffffffffffffff000000000000","4d37c850644563c69fd0acd9a049325b", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "80","00000000000000000000000000000000","ffffffffffffffffffff800000000000","b87c921b91829ef3b13ca541ee1130a6", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "81","00000000000000000000000000000000","ffffffffffffffffffffc00000000000","2e65eb6b6ea383e109accce8326b0393", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "82","00000000000000000000000000000000","ffffffffffffffffffffe00000000000","9ca547f7439edc3e255c0f4d49aa8990", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "83","00000000000000000000000000000000","fffffffffffffffffffff00000000000","a5e652614c9300f37816b1f9fd0c87f9", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "84","00000000000000000000000000000000","fffffffffffffffffffff80000000000","14954f0b4697776f44494fe458d814ed", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "85","00000000000000000000000000000000","fffffffffffffffffffffc0000000000","7c8d9ab6c2761723fe42f8bb506cbcf7", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "86","00000000000000000000000000000000","fffffffffffffffffffffe0000000000","db7e1932679fdd99742aab04aa0d5a80", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "87","00000000000000000000000000000000","ffffffffffffffffffffff0000000000","4c6a1c83e568cd10f27c2d73ded19c28", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "88","00000000000000000000000000000000","ffffffffffffffffffffff8000000000","90ecbe6177e674c98de412413f7ac915", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "89","00000000000000000000000000000000","ffffffffffffffffffffffc000000000","90684a2ac55fe1ec2b8ebd5622520b73", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "90","00000000000000000000000000000000","ffffffffffffffffffffffe000000000","7472f9a7988607ca79707795991035e6", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "91","00000000000000000000000000000000","fffffffffffffffffffffff000000000","56aff089878bf3352f8df172a3ae47d8", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "92","00000000000000000000000000000000","fffffffffffffffffffffff800000000","65c0526cbe40161b8019a2a3171abd23", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "93","00000000000000000000000000000000","fffffffffffffffffffffffc00000000","377be0be33b4e3e310b4aabda173f84f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "94","00000000000000000000000000000000","fffffffffffffffffffffffe00000000","9402e9aa6f69de6504da8d20c4fcaa2f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "95","00000000000000000000000000000000","ffffffffffffffffffffffff00000000","123c1f4af313ad8c2ce648b2e71fb6e1", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "96","00000000000000000000000000000000","ffffffffffffffffffffffff80000000","1ffc626d30203dcdb0019fb80f726cf4", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "97","00000000000000000000000000000000","ffffffffffffffffffffffffc0000000","76da1fbe3a50728c50fd2e621b5ad885", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "98","00000000000000000000000000000000","ffffffffffffffffffffffffe0000000","082eb8be35f442fb52668e16a591d1d6", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "99","00000000000000000000000000000000","fffffffffffffffffffffffff0000000","e656f9ecf5fe27ec3e4a73d00c282fb3", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "100","00000000000000000000000000000000","fffffffffffffffffffffffff8000000","2ca8209d63274cd9a29bb74bcd77683a", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "101","00000000000000000000000000000000","fffffffffffffffffffffffffc000000","79bf5dce14bb7dd73a8e3611de7ce026", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "102","00000000000000000000000000000000","fffffffffffffffffffffffffe000000","3c849939a5d29399f344c4a0eca8a576", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "103","00000000000000000000000000000000","ffffffffffffffffffffffffff000000","ed3c0a94d59bece98835da7aa4f07ca2", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "104","00000000000000000000000000000000","ffffffffffffffffffffffffff800000","63919ed4ce10196438b6ad09d99cd795", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "105","00000000000000000000000000000000","ffffffffffffffffffffffffffc00000","7678f3a833f19fea95f3c6029e2bc610", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "106","00000000000000000000000000000000","ffffffffffffffffffffffffffe00000","3aa426831067d36b92be7c5f81c13c56", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "107","00000000000000000000000000000000","fffffffffffffffffffffffffff00000","9272e2d2cdd11050998c845077a30ea0", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "108","00000000000000000000000000000000","fffffffffffffffffffffffffff80000","088c4b53f5ec0ff814c19adae7f6246c", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "109","00000000000000000000000000000000","fffffffffffffffffffffffffffc0000","4010a5e401fdf0a0354ddbcc0d012b17", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "110","00000000000000000000000000000000","fffffffffffffffffffffffffffe0000","a87a385736c0a6189bd6589bd8445a93", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "111","00000000000000000000000000000000","ffffffffffffffffffffffffffff0000","545f2b83d9616dccf60fa9830e9cd287", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "112","00000000000000000000000000000000","ffffffffffffffffffffffffffff8000","4b706f7f92406352394037a6d4f4688d", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "113","00000000000000000000000000000000","ffffffffffffffffffffffffffffc000","b7972b3941c44b90afa7b264bfba7387", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "114","00000000000000000000000000000000","ffffffffffffffffffffffffffffe000","6f45732cf10881546f0fd23896d2bb60", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "115","00000000000000000000000000000000","fffffffffffffffffffffffffffff000","2e3579ca15af27f64b3c955a5bfc30ba", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "116","00000000000000000000000000000000","fffffffffffffffffffffffffffff800","34a2c5a91ae2aec99b7d1b5fa6780447", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "117","00000000000000000000000000000000","fffffffffffffffffffffffffffffc00","a4d6616bd04f87335b0e53351227a9ee", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "118","00000000000000000000000000000000","fffffffffffffffffffffffffffffe00","7f692b03945867d16179a8cefc83ea3f", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "119","00000000000000000000000000000000","ffffffffffffffffffffffffffffff00","3bd141ee84a0e6414a26e7a4f281f8a2", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "120","00000000000000000000000000000000","ffffffffffffffffffffffffffffff80","d1788f572d98b2b16ec5d5f3922b99bc", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "121","00000000000000000000000000000000","ffffffffffffffffffffffffffffffc0","0833ff6f61d98a57b288e8c3586b85a6", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "122","00000000000000000000000000000000","ffffffffffffffffffffffffffffffe0","8568261797de176bf0b43becc6285afb", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "123","00000000000000000000000000000000","fffffffffffffffffffffffffffffff0","f9b0fda0c4a898f5b9e6f661c4ce4d07", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "124","00000000000000000000000000000000","fffffffffffffffffffffffffffffff8","8ade895913685c67c5269f8aae42983e", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "125","00000000000000000000000000000000","fffffffffffffffffffffffffffffffc","39bde67d5c8ed8a8b1c37eb8fa9f5ac0", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "126","00000000000000000000000000000000","fffffffffffffffffffffffffffffffe","5c005e72c1418c44f569f2ea33ba54f3", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "127","00000000000000000000000000000000","ffffffffffffffffffffffffffffffff","3f5b8cc9ea855a0afa7347d23e8d664e", false);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "0","00000000000000000000000000000000","3ad78e726c1ec02b7ebfe92b23d9ec34","80000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "1","00000000000000000000000000000000","aae5939c8efdf2f04e60b9fe7117b2c2","c0000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "2","00000000000000000000000000000000","f031d4d74f5dcbf39daaf8ca3af6e527","e0000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "3","00000000000000000000000000000000","96d9fd5cc4f07441727df0f33e401a36","f0000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "4","00000000000000000000000000000000","30ccdb044646d7e1f3ccea3dca08b8c0","f8000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "5","00000000000000000000000000000000","16ae4ce5042a67ee8e177b7c587ecc82","fc000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "6","00000000000000000000000000000000","b6da0bb11a23855d9c5cb1b4c6412e0a","fe000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "7","00000000000000000000000000000000","db4f1aa530967d6732ce4715eb0ee24b","ff000000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "8","00000000000000000000000000000000","a81738252621dd180a34f3455b4baa2f","ff800000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "9","00000000000000000000000000000000","77e2b508db7fd89234caf7939ee5621a","ffc00000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "10","00000000000000000000000000000000","b8499c251f8442ee13f0933b688fcd19","ffe00000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "11","00000000000000000000000000000000","965135f8a81f25c9d630b17502f68e53","fff00000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "12","00000000000000000000000000000000","8b87145a01ad1c6cede995ea3670454f","fff80000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "13","00000000000000000000000000000000","8eae3b10a0c8ca6d1d3b0fa61e56b0b2","fffc0000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "14","00000000000000000000000000000000","64b4d629810fda6bafdf08f3b0d8d2c5","fffe0000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "15","00000000000000000000000000000000","d7e5dbd3324595f8fdc7d7c571da6c2a","ffff0000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "16","00000000000000000000000000000000","f3f72375264e167fca9de2c1527d9606","ffff8000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "17","00000000000000000000000000000000","8ee79dd4f401ff9b7ea945d86666c13b","ffffc000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "18","00000000000000000000000000000000","dd35cea2799940b40db3f819cb94c08b","ffffe000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "19","00000000000000000000000000000000","6941cb6b3e08c2b7afa581ebdd607b87","fffff000000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "20","00000000000000000000000000000000","2c20f439f6bb097b29b8bd6d99aad799","fffff800000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "21","00000000000000000000000000000000","625d01f058e565f77ae86378bd2c49b3","fffffc00000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "22","00000000000000000000000000000000","c0b5fd98190ef45fbb4301438d095950","fffffe00000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "23","00000000000000000000000000000000","13001ff5d99806efd25da34f56be854b","ffffff00000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "24","00000000000000000000000000000000","3b594c60f5c8277a5113677f94208d82","ffffff80000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "25","00000000000000000000000000000000","e9c0fc1818e4aa46bd2e39d638f89e05","ffffffc0000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "26","00000000000000000000000000000000","f8023ee9c3fdc45a019b4e985c7e1a54","ffffffe0000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "27","00000000000000000000000000000000","35f40182ab4662f3023baec1ee796b57","fffffff0000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "28","00000000000000000000000000000000","3aebbad7303649b4194a6945c6cc3694","fffffff8000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "29","00000000000000000000000000000000","a2124bea53ec2834279bed7f7eb0f938","fffffffc000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "30","00000000000000000000000000000000","b9fb4399fa4facc7309e14ec98360b0a","fffffffe000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "31","00000000000000000000000000000000","c26277437420c5d634f715aea81a9132","ffffffff000000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "32","00000000000000000000000000000000","171a0e1b2dd424f0e089af2c4c10f32f","ffffffff800000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "33","00000000000000000000000000000000","7cadbe402d1b208fe735edce00aee7ce","ffffffffc00000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "34","00000000000000000000000000000000","43b02ff929a1485af6f5c6d6558baa0f","ffffffffe00000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "35","00000000000000000000000000000000","092faacc9bf43508bf8fa8613ca75dea","fffffffff00000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "36","00000000000000000000000000000000","cb2bf8280f3f9742c7ed513fe802629c","fffffffff80000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "37","00000000000000000000000000000000","215a41ee442fa992a6e323986ded3f68","fffffffffc0000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "38","00000000000000000000000000000000","f21e99cf4f0f77cea836e11a2fe75fb1","fffffffffe0000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "39","00000000000000000000000000000000","95e3a0ca9079e646331df8b4e70d2cd6","ffffffffff0000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "40","00000000000000000000000000000000","4afe7f120ce7613f74fc12a01a828073","ffffffffff8000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "41","00000000000000000000000000000000","827f000e75e2c8b9d479beed913fe678","ffffffffffc000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "42","00000000000000000000000000000000","35830c8e7aaefe2d30310ef381cbf691","ffffffffffe000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "43","00000000000000000000000000000000","191aa0f2c8570144f38657ea4085ebe5","fffffffffff000000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "44","00000000000000000000000000000000","85062c2c909f15d9269b6c18ce99c4f0","fffffffffff800000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "45","00000000000000000000000000000000","678034dc9e41b5a560ed239eeab1bc78","fffffffffffc00000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "46","00000000000000000000000000000000","c2f93a4ce5ab6d5d56f1b93cf19911c1","fffffffffffe00000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "47","00000000000000000000000000000000","1c3112bcb0c1dcc749d799743691bf82","ffffffffffff00000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "48","00000000000000000000000000000000","00c55bd75c7f9c881989d3ec1911c0d4","ffffffffffff80000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "49","00000000000000000000000000000000","ea2e6b5ef182b7dff3629abd6a12045f","ffffffffffffc0000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "50","00000000000000000000000000000000","22322327e01780b17397f24087f8cc6f","ffffffffffffe0000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "51","00000000000000000000000000000000","c9cacb5cd11692c373b2411768149ee7","fffffffffffff0000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "52","00000000000000000000000000000000","a18e3dbbca577860dab6b80da3139256","fffffffffffff8000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "53","00000000000000000000000000000000","79b61c37bf328ecca8d743265a3d425c","fffffffffffffc000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "54","00000000000000000000000000000000","d2d99c6bcc1f06fda8e27e8ae3f1ccc7","fffffffffffffe000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "55","00000000000000000000000000000000","1bfd4b91c701fd6b61b7f997829d663b","ffffffffffffff000000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "56","00000000000000000000000000000000","11005d52f25f16bdc9545a876a63490a","ffffffffffffff800000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "57","00000000000000000000000000000000","3a4d354f02bb5a5e47d39666867f246a","ffffffffffffffc00000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "58","00000000000000000000000000000000","d451b8d6e1e1a0ebb155fbbf6e7b7dc3","ffffffffffffffe00000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "59","00000000000000000000000000000000","6898d4f42fa7ba6a10ac05e87b9f2080","fffffffffffffff00000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "60","00000000000000000000000000000000","b611295e739ca7d9b50f8e4c0e754a3f","fffffffffffffff80000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "61","00000000000000000000000000000000","7d33fc7d8abe3ca1936759f8f5deaf20","fffffffffffffffc0000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "62","00000000000000000000000000000000","3b5e0f566dc96c298f0c12637539b25c","fffffffffffffffe0000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "63","00000000000000000000000000000000","f807c3e7985fe0f5a50e2cdb25c5109e","ffffffffffffffff0000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "64","00000000000000000000000000000000","41f992a856fb278b389a62f5d274d7e9","ffffffffffffffff8000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "65","00000000000000000000000000000000","10d3ed7a6fe15ab4d91acbc7d0767ab1","ffffffffffffffffc000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "66","00000000000000000000000000000000","21feecd45b2e675973ac33bf0c5424fc","ffffffffffffffffe000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "67","00000000000000000000000000000000","1480cb3955ba62d09eea668f7c708817","fffffffffffffffff000000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "68","00000000000000000000000000000000","66404033d6b72b609354d5496e7eb511","fffffffffffffffff800000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "69","00000000000000000000000000000000","1c317a220a7d700da2b1e075b00266e1","fffffffffffffffffc00000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "70","00000000000000000000000000000000","ab3b89542233f1271bf8fd0c0f403545","fffffffffffffffffe00000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "71","00000000000000000000000000000000","d93eae966fac46dca927d6b114fa3f9e","ffffffffffffffffff00000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "72","00000000000000000000000000000000","1bdec521316503d9d5ee65df3ea94ddf","ffffffffffffffffff80000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "73","00000000000000000000000000000000","eef456431dea8b4acf83bdae3717f75f","ffffffffffffffffffc0000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "74","00000000000000000000000000000000","06f2519a2fafaa596bfef5cfa15c21b9","ffffffffffffffffffe0000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "75","00000000000000000000000000000000","251a7eac7e2fe809e4aa8d0d7012531a","fffffffffffffffffff0000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "76","00000000000000000000000000000000","3bffc16e4c49b268a20f8d96a60b4058","fffffffffffffffffff8000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "77","00000000000000000000000000000000","e886f9281999c5bb3b3e8862e2f7c988","fffffffffffffffffffc000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "78","00000000000000000000000000000000","563bf90d61beef39f48dd625fcef1361","fffffffffffffffffffe000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "79","00000000000000000000000000000000","4d37c850644563c69fd0acd9a049325b","ffffffffffffffffffff000000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "80","00000000000000000000000000000000","b87c921b91829ef3b13ca541ee1130a6","ffffffffffffffffffff800000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "81","00000000000000000000000000000000","2e65eb6b6ea383e109accce8326b0393","ffffffffffffffffffffc00000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "82","00000000000000000000000000000000","9ca547f7439edc3e255c0f4d49aa8990","ffffffffffffffffffffe00000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "83","00000000000000000000000000000000","a5e652614c9300f37816b1f9fd0c87f9","fffffffffffffffffffff00000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "84","00000000000000000000000000000000","14954f0b4697776f44494fe458d814ed","fffffffffffffffffffff80000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "85","00000000000000000000000000000000","7c8d9ab6c2761723fe42f8bb506cbcf7","fffffffffffffffffffffc0000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "86","00000000000000000000000000000000","db7e1932679fdd99742aab04aa0d5a80","fffffffffffffffffffffe0000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "87","00000000000000000000000000000000","4c6a1c83e568cd10f27c2d73ded19c28","ffffffffffffffffffffff0000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "88","00000000000000000000000000000000","90ecbe6177e674c98de412413f7ac915","ffffffffffffffffffffff8000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "89","00000000000000000000000000000000","90684a2ac55fe1ec2b8ebd5622520b73","ffffffffffffffffffffffc000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "90","00000000000000000000000000000000","7472f9a7988607ca79707795991035e6","ffffffffffffffffffffffe000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "91","00000000000000000000000000000000","56aff089878bf3352f8df172a3ae47d8","fffffffffffffffffffffff000000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "92","00000000000000000000000000000000","65c0526cbe40161b8019a2a3171abd23","fffffffffffffffffffffff800000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "93","00000000000000000000000000000000","377be0be33b4e3e310b4aabda173f84f","fffffffffffffffffffffffc00000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "94","00000000000000000000000000000000","9402e9aa6f69de6504da8d20c4fcaa2f","fffffffffffffffffffffffe00000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "95","00000000000000000000000000000000","123c1f4af313ad8c2ce648b2e71fb6e1","ffffffffffffffffffffffff00000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "96","00000000000000000000000000000000","1ffc626d30203dcdb0019fb80f726cf4","ffffffffffffffffffffffff80000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "97","00000000000000000000000000000000","76da1fbe3a50728c50fd2e621b5ad885","ffffffffffffffffffffffffc0000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "98","00000000000000000000000000000000","082eb8be35f442fb52668e16a591d1d6","ffffffffffffffffffffffffe0000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "99","00000000000000000000000000000000","e656f9ecf5fe27ec3e4a73d00c282fb3","fffffffffffffffffffffffff0000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "100","00000000000000000000000000000000","2ca8209d63274cd9a29bb74bcd77683a","fffffffffffffffffffffffff8000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "101","00000000000000000000000000000000","79bf5dce14bb7dd73a8e3611de7ce026","fffffffffffffffffffffffffc000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "102","00000000000000000000000000000000","3c849939a5d29399f344c4a0eca8a576","fffffffffffffffffffffffffe000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "103","00000000000000000000000000000000","ed3c0a94d59bece98835da7aa4f07ca2","ffffffffffffffffffffffffff000000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "104","00000000000000000000000000000000","63919ed4ce10196438b6ad09d99cd795","ffffffffffffffffffffffffff800000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "105","00000000000000000000000000000000","7678f3a833f19fea95f3c6029e2bc610","ffffffffffffffffffffffffffc00000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "106","00000000000000000000000000000000","3aa426831067d36b92be7c5f81c13c56","ffffffffffffffffffffffffffe00000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "107","00000000000000000000000000000000","9272e2d2cdd11050998c845077a30ea0","fffffffffffffffffffffffffff00000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "108","00000000000000000000000000000000","088c4b53f5ec0ff814c19adae7f6246c","fffffffffffffffffffffffffff80000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "109","00000000000000000000000000000000","4010a5e401fdf0a0354ddbcc0d012b17","fffffffffffffffffffffffffffc0000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "110","00000000000000000000000000000000","a87a385736c0a6189bd6589bd8445a93","fffffffffffffffffffffffffffe0000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "111","00000000000000000000000000000000","545f2b83d9616dccf60fa9830e9cd287","ffffffffffffffffffffffffffff0000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "112","00000000000000000000000000000000","4b706f7f92406352394037a6d4f4688d","ffffffffffffffffffffffffffff8000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "113","00000000000000000000000000000000","b7972b3941c44b90afa7b264bfba7387","ffffffffffffffffffffffffffffc000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "114","00000000000000000000000000000000","6f45732cf10881546f0fd23896d2bb60","ffffffffffffffffffffffffffffe000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "115","00000000000000000000000000000000","2e3579ca15af27f64b3c955a5bfc30ba","fffffffffffffffffffffffffffff000", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "116","00000000000000000000000000000000","34a2c5a91ae2aec99b7d1b5fa6780447","fffffffffffffffffffffffffffff800", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "117","00000000000000000000000000000000","a4d6616bd04f87335b0e53351227a9ee","fffffffffffffffffffffffffffffc00", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "118","00000000000000000000000000000000","7f692b03945867d16179a8cefc83ea3f","fffffffffffffffffffffffffffffe00", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "119","00000000000000000000000000000000","3bd141ee84a0e6414a26e7a4f281f8a2","ffffffffffffffffffffffffffffff00", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "120","00000000000000000000000000000000","d1788f572d98b2b16ec5d5f3922b99bc","ffffffffffffffffffffffffffffff80", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "121","00000000000000000000000000000000","0833ff6f61d98a57b288e8c3586b85a6","ffffffffffffffffffffffffffffffc0", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "122","00000000000000000000000000000000","8568261797de176bf0b43becc6285afb","ffffffffffffffffffffffffffffffe0", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "123","00000000000000000000000000000000","f9b0fda0c4a898f5b9e6f661c4ce4d07","fffffffffffffffffffffffffffffff0", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "124","00000000000000000000000000000000","8ade895913685c67c5269f8aae42983e","fffffffffffffffffffffffffffffff8", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "125","00000000000000000000000000000000","39bde67d5c8ed8a8b1c37eb8fa9f5ac0","fffffffffffffffffffffffffffffffc", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "126","00000000000000000000000000000000","5c005e72c1418c44f569f2ea33ba54f3","fffffffffffffffffffffffffffffffe", true);
    aes_test(maid_aes_128, "ECBVarTxt128.rsp", "127","00000000000000000000000000000000","3f5b8cc9ea855a0afa7347d23e8d664e","ffffffffffffffffffffffffffffffff", true);
}

static void
aes_test_gfsbox_192(void)
{
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "0","000000000000000000000000000000000000000000000000","1b077a6af4b7f98229de786d7516b639","275cfc0413d8ccb70513c3859b1d0f72", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "1","000000000000000000000000000000000000000000000000","9c2d8842e5f48f57648205d39a239af1","c9b8135ff1b5adc413dfd053b21bd96d", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "2","000000000000000000000000000000000000000000000000","bff52510095f518ecca60af4205444bb","4a3650c3371ce2eb35e389a171427440", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "3","000000000000000000000000000000000000000000000000","51719783d3185a535bd75adc65071ce1","4f354592ff7c8847d2d0870ca9481b7c", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "4","000000000000000000000000000000000000000000000000","26aa49dcfe7629a8901a69a9914e6dfd","d5e08bf9a182e857cf40b3a36ee248cc", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "5","000000000000000000000000000000000000000000000000","941a4773058224e1ef66d10e0a6ee782","067cd9d3749207791841562507fa9626", false);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "0","000000000000000000000000000000000000000000000000","275cfc0413d8ccb70513c3859b1d0f72","1b077a6af4b7f98229de786d7516b639", true);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "1","000000000000000000000000000000000000000000000000","c9b8135ff1b5adc413dfd053b21bd96d","9c2d8842e5f48f57648205d39a239af1", true);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "2","000000000000000000000000000000000000000000000000","4a3650c3371ce2eb35e389a171427440","bff52510095f518ecca60af4205444bb", true);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "3","000000000000000000000000000000000000000000000000","4f354592ff7c8847d2d0870ca9481b7c","51719783d3185a535bd75adc65071ce1", true);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "4","000000000000000000000000000000000000000000000000","d5e08bf9a182e857cf40b3a36ee248cc","26aa49dcfe7629a8901a69a9914e6dfd", true);
    aes_test(maid_aes_192, "ECBGFSbox192.rsp", "5","000000000000000000000000000000000000000000000000","067cd9d3749207791841562507fa9626","941a4773058224e1ef66d10e0a6ee782", true);
}

static void
aes_test_keysbox_192(void)
{
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "0","e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd","00000000000000000000000000000000","0956259c9cd5cfd0181cca53380cde06", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "1","15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29","00000000000000000000000000000000","8e4e18424e591a3d5b6f0876f16f8594", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "2","a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c","00000000000000000000000000000000","93f3270cfc877ef17e106ce938979cb0", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "3","cd62376d5ebb414917f0c78f05266433dc9192a1ec943300","00000000000000000000000000000000","7f6c25ff41858561bb62f36492e93c29", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "4","502a6ab36984af268bf423c7f509205207fc1552af4a91e5","00000000000000000000000000000000","8e06556dcbb00b809a025047cff2a940", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "5","25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce","00000000000000000000000000000000","3608c344868e94555d23a120f8a5502d", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "6","e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53","00000000000000000000000000000000","77da2021935b840b7f5dcc39132da9e5", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "7","3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980","00000000000000000000000000000000","3b7c24f825e3bf9873c9f14d39a0e6f4", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "8","950bb9f22cc35be6fe79f52c320af93dec5bc9c0c2f9cd53","00000000000000000000000000000000","64ebf95686b353508c90ecd8b6134316", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "9","7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40","00000000000000000000000000000000","ff558c5d27210b7929b73fc708eb4cf1", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "10","f029ce61d4e5a405b41ead0a883cc6a737da2cf50a6c92ae","00000000000000000000000000000000","a2c3b2a818075490a7b4c14380f02702", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "11","61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79","00000000000000000000000000000000","cfe4d74002696ccf7d87b14a2f9cafc9", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "12","b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570","00000000000000000000000000000000","d2eafd86f63b109b91f5dbb3a3fb7e13", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "13","ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6","00000000000000000000000000000000","9b9fdd1c5975655f539998b306a324af", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "14","d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3","00000000000000000000000000000000","dd619e1cf204446112e0af2b9afa8f8c", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "15","982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93","00000000000000000000000000000000","d4f0aae13c8fe9339fbf9e69ed0ad74d", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "16","98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9","00000000000000000000000000000000","19c80ec4a6deb7e5ed1033dda933498f", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "17","b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35","00000000000000000000000000000000","3cf5e1d21a17956d1dffad6a7c41c659", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "18","45899367c3132849763073c435a9288a766c8b9ec2308516","00000000000000000000000000000000","69fd12e8505f8ded2fdcb197a121b362", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "19","ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e","00000000000000000000000000000000","8aa584e2cc4d17417a97cb9a28ba29c8", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "20","d077a03bd8a38973928ccafe4a9d2f455130bd0af5ae46a9","00000000000000000000000000000000","abc786fb1edb504580c4d882ef29a0c7", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "21","d184c36cf0dddfec39e654195006022237871a47c33d3198","00000000000000000000000000000000","2e19fb60a3e1de0166f483c97824a978", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "22","4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080","00000000000000000000000000000000","7656709538dd5fec41e0ce6a0f8e207d", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "23","c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72","00000000000000000000000000000000","a67cf333b314d411d3c0ae6e1cfcd8f5", false);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "0","e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd","0956259c9cd5cfd0181cca53380cde06","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "1","15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29","8e4e18424e591a3d5b6f0876f16f8594","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "2","a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c","93f3270cfc877ef17e106ce938979cb0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "3","cd62376d5ebb414917f0c78f05266433dc9192a1ec943300","7f6c25ff41858561bb62f36492e93c29","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "4","502a6ab36984af268bf423c7f509205207fc1552af4a91e5","8e06556dcbb00b809a025047cff2a940","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "5","25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce","3608c344868e94555d23a120f8a5502d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "6","e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53","77da2021935b840b7f5dcc39132da9e5","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "7","3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980","3b7c24f825e3bf9873c9f14d39a0e6f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "8","950bb9f22cc35be6fe79f52c320af93dec5bc9c0c2f9cd53","64ebf95686b353508c90ecd8b6134316","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "9","7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40","ff558c5d27210b7929b73fc708eb4cf1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "10","f029ce61d4e5a405b41ead0a883cc6a737da2cf50a6c92ae","a2c3b2a818075490a7b4c14380f02702","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "11","61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79","cfe4d74002696ccf7d87b14a2f9cafc9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "12","b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570","d2eafd86f63b109b91f5dbb3a3fb7e13","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "13","ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6","9b9fdd1c5975655f539998b306a324af","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "14","d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3","dd619e1cf204446112e0af2b9afa8f8c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "15","982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93","d4f0aae13c8fe9339fbf9e69ed0ad74d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "16","98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9","19c80ec4a6deb7e5ed1033dda933498f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "17","b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35","3cf5e1d21a17956d1dffad6a7c41c659","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "18","45899367c3132849763073c435a9288a766c8b9ec2308516","69fd12e8505f8ded2fdcb197a121b362","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "19","ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e","8aa584e2cc4d17417a97cb9a28ba29c8","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "20","d077a03bd8a38973928ccafe4a9d2f455130bd0af5ae46a9","abc786fb1edb504580c4d882ef29a0c7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "21","d184c36cf0dddfec39e654195006022237871a47c33d3198","2e19fb60a3e1de0166f483c97824a978","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "22","4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080","7656709538dd5fec41e0ce6a0f8e207d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBKeySbox192.rsp", "23","c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72","a67cf333b314d411d3c0ae6e1cfcd8f5","00000000000000000000000000000000", true);
}

static void
aes_test_varkey_192(void)
{
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "0","800000000000000000000000000000000000000000000000","00000000000000000000000000000000","de885dc87f5a92594082d02cc1e1b42c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "1","c00000000000000000000000000000000000000000000000","00000000000000000000000000000000","132b074e80f2a597bf5febd8ea5da55e", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "2","e00000000000000000000000000000000000000000000000","00000000000000000000000000000000","6eccedf8de592c22fb81347b79f2db1f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "3","f00000000000000000000000000000000000000000000000","00000000000000000000000000000000","180b09f267c45145db2f826c2582d35c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "4","f80000000000000000000000000000000000000000000000","00000000000000000000000000000000","edd807ef7652d7eb0e13c8b5e15b3bc0", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "5","fc0000000000000000000000000000000000000000000000","00000000000000000000000000000000","9978bcf8dd8fd72241223ad24b31b8a4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "6","fe0000000000000000000000000000000000000000000000","00000000000000000000000000000000","5310f654343e8f27e12c83a48d24ff81", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "7","ff0000000000000000000000000000000000000000000000","00000000000000000000000000000000","833f71258d53036b02952c76c744f5a1", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "8","ff8000000000000000000000000000000000000000000000","00000000000000000000000000000000","eba83ff200cff9318a92f8691a06b09f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "9","ffc000000000000000000000000000000000000000000000","00000000000000000000000000000000","ff620ccbe9f3292abdf2176b09f04eba", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "10","ffe000000000000000000000000000000000000000000000","00000000000000000000000000000000","7ababc4b3f516c9aafb35f4140b548f9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "11","fff000000000000000000000000000000000000000000000","00000000000000000000000000000000","aa187824d9c4582b0916493ecbde8c57", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "12","fff800000000000000000000000000000000000000000000","00000000000000000000000000000000","1c0ad553177fd5ea1092c9d626a29dc4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "13","fffc00000000000000000000000000000000000000000000","00000000000000000000000000000000","a5dc46c37261194124ecaebd680408ec", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "14","fffe00000000000000000000000000000000000000000000","00000000000000000000000000000000","e4f2f2ae23e9b10bacfa58601531ba54", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "15","ffff00000000000000000000000000000000000000000000","00000000000000000000000000000000","b7d67cf1a1e91e8ff3a57a172c7bf412", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "16","ffff80000000000000000000000000000000000000000000","00000000000000000000000000000000","26706be06967884e847d137128ce47b3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "17","ffffc0000000000000000000000000000000000000000000","00000000000000000000000000000000","b2f8b409b0585909aad3a7b5a219072a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "18","ffffe0000000000000000000000000000000000000000000","00000000000000000000000000000000","5e4b7bff0290c78344c54a23b722cd20", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "19","fffff0000000000000000000000000000000000000000000","00000000000000000000000000000000","07093657552d4414227ce161e9ebf7dd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "20","fffff8000000000000000000000000000000000000000000","00000000000000000000000000000000","e1af1e7d8bc225ed4dffb771ecbb9e67", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "21","fffffc000000000000000000000000000000000000000000","00000000000000000000000000000000","ef6555253635d8432156cfd9c11b145a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "22","fffffe000000000000000000000000000000000000000000","00000000000000000000000000000000","fb4035074a5d4260c90cbd6da6c3fceb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "23","ffffff000000000000000000000000000000000000000000","00000000000000000000000000000000","446ee416f9ad1c103eb0cc96751c88e1", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "24","ffffff800000000000000000000000000000000000000000","00000000000000000000000000000000","198ae2a4637ac0a7890a8fd1485445c9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "25","ffffffc00000000000000000000000000000000000000000","00000000000000000000000000000000","562012ec8faded0825fb2fa70ab30cbd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "26","ffffffe00000000000000000000000000000000000000000","00000000000000000000000000000000","cc8a64b46b5d88bf7f247d4dbaf38f05", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "27","fffffff00000000000000000000000000000000000000000","00000000000000000000000000000000","a168253762e2cc81b42d1e5001762699", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "28","fffffff80000000000000000000000000000000000000000","00000000000000000000000000000000","1b41f83b38ce5032c6cd7af98cf62061", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "29","fffffffc0000000000000000000000000000000000000000","00000000000000000000000000000000","61a89990cd1411750d5fb0dc988447d4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "30","fffffffe0000000000000000000000000000000000000000","00000000000000000000000000000000","b5accc8ed629edf8c68a539183b1ea82", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "31","ffffffff0000000000000000000000000000000000000000","00000000000000000000000000000000","b16fa71f846b81a13f361c43a851f290", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "32","ffffffff8000000000000000000000000000000000000000","00000000000000000000000000000000","4fad6efdff5975aee7692234bcd54488", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "33","ffffffffc000000000000000000000000000000000000000","00000000000000000000000000000000","ebfdb05a783d03082dfe5fdd80a00b17", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "34","ffffffffe000000000000000000000000000000000000000","00000000000000000000000000000000","eb81b584766997af6ba5529d3bdd8609", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "35","fffffffff000000000000000000000000000000000000000","00000000000000000000000000000000","0cf4ff4f49c8a0ca060c443499e29313", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "36","fffffffff800000000000000000000000000000000000000","00000000000000000000000000000000","cc4ba8a8e029f8b26d8afff9df133bb6", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "37","fffffffffc00000000000000000000000000000000000000","00000000000000000000000000000000","fefebf64360f38e4e63558f0ffc550c3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "38","fffffffffe00000000000000000000000000000000000000","00000000000000000000000000000000","12ad98cbf725137d6a8108c2bed99322", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "39","ffffffffff00000000000000000000000000000000000000","00000000000000000000000000000000","6afaa996226198b3e2610413ce1b3f78", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "40","ffffffffff80000000000000000000000000000000000000","00000000000000000000000000000000","2a8ce6747a7e39367828e290848502d9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "41","ffffffffffc0000000000000000000000000000000000000","00000000000000000000000000000000","223736e8b8f89ca1e37b6deab40facf1", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "42","ffffffffffe0000000000000000000000000000000000000","00000000000000000000000000000000","c0f797e50418b95fa6013333917a9480", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "43","fffffffffff0000000000000000000000000000000000000","00000000000000000000000000000000","a758de37c2ece2a02c73c01fedc9a132", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "44","fffffffffff8000000000000000000000000000000000000","00000000000000000000000000000000","3a9b87ae77bae706803966c66c73adbd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "45","fffffffffffc000000000000000000000000000000000000","00000000000000000000000000000000","d365ab8df8ffd782e358121a4a4fc541", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "46","fffffffffffe000000000000000000000000000000000000","00000000000000000000000000000000","c8dcd9e6f75e6c36c8daee0466f0ed74", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "47","ffffffffffff000000000000000000000000000000000000","00000000000000000000000000000000","c79a637beb1c0304f14014c037e736dd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "48","ffffffffffff800000000000000000000000000000000000","00000000000000000000000000000000","105f0a25e84ac930d996281a5f954dd9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "49","ffffffffffffc00000000000000000000000000000000000","00000000000000000000000000000000","42e4074b2927973e8d17ffa92f7fe615", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "50","ffffffffffffe00000000000000000000000000000000000","00000000000000000000000000000000","4fe2a9d2c1824449c69e3e0398f12963", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "51","fffffffffffff00000000000000000000000000000000000","00000000000000000000000000000000","b7f29c1e1f62847a15253b28a1e9d712", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "52","fffffffffffff80000000000000000000000000000000000","00000000000000000000000000000000","36ed5d29b903f31e8983ef8b0a2bf990", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "53","fffffffffffffc0000000000000000000000000000000000","00000000000000000000000000000000","27b8070270810f9d023f9dd7ff3b4aa2", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "54","fffffffffffffe0000000000000000000000000000000000","00000000000000000000000000000000","94d46e155c1228f61d1a0db4815ecc4b", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "55","ffffffffffffff0000000000000000000000000000000000","00000000000000000000000000000000","ca6108d1d98071428eeceef1714b96dd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "56","ffffffffffffff8000000000000000000000000000000000","00000000000000000000000000000000","dc5b25b71b6296cf73dd2cdcac2f70b1", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "57","ffffffffffffffc000000000000000000000000000000000","00000000000000000000000000000000","44aba95e8a06a2d9d3530d2677878c80", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "58","ffffffffffffffe000000000000000000000000000000000","00000000000000000000000000000000","a570d20e89b467e8f5176061b81dd396", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "59","fffffffffffffff000000000000000000000000000000000","00000000000000000000000000000000","758f4467a5d8f1e7307dc30b34e404f4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "60","fffffffffffffff800000000000000000000000000000000","00000000000000000000000000000000","bcea28e9071b5a2302970ff352451bc5", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "61","fffffffffffffffc00000000000000000000000000000000","00000000000000000000000000000000","7523c00bc177d331ad312e09c9015c1c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "62","fffffffffffffffe00000000000000000000000000000000","00000000000000000000000000000000","ccac61e3183747b3f5836da21a1bc4f4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "63","ffffffffffffffff00000000000000000000000000000000","00000000000000000000000000000000","707b075791878880b44189d3522b8c30", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "64","ffffffffffffffff80000000000000000000000000000000","00000000000000000000000000000000","7132d0c0e4a07593cf12ebb12be7688c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "65","ffffffffffffffffc0000000000000000000000000000000","00000000000000000000000000000000","effbac1644deb0c784275fe56e19ead3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "66","ffffffffffffffffe0000000000000000000000000000000","00000000000000000000000000000000","a005063f30f4228b374e2459738f26bb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "67","fffffffffffffffff0000000000000000000000000000000","00000000000000000000000000000000","29975b5f48bb68fcbbc7cea93b452ed7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "68","fffffffffffffffff8000000000000000000000000000000","00000000000000000000000000000000","cf3f2576e2afedc74bb1ca7eeec1c0e7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "69","fffffffffffffffffc000000000000000000000000000000","00000000000000000000000000000000","07c403f5f966e0e3d9f296d6226dca28", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "70","fffffffffffffffffe000000000000000000000000000000","00000000000000000000000000000000","c8c20908249ab4a34d6dd0a31327ff1a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "71","ffffffffffffffffff000000000000000000000000000000","00000000000000000000000000000000","c0541329ecb6159ab23b7fc5e6a21bca", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "72","ffffffffffffffffff800000000000000000000000000000","00000000000000000000000000000000","7aa1acf1a2ed9ba72bc6deb31d88b863", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "73","ffffffffffffffffffc00000000000000000000000000000","00000000000000000000000000000000","808bd8eddabb6f3bf0d5a8a27be1fe8a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "74","ffffffffffffffffffe00000000000000000000000000000","00000000000000000000000000000000","273c7d7685e14ec66bbb96b8f05b6ddd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "75","fffffffffffffffffff00000000000000000000000000000","00000000000000000000000000000000","32752eefc8c2a93f91b6e73eb07cca6e", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "76","fffffffffffffffffff80000000000000000000000000000","00000000000000000000000000000000","d893e7d62f6ce502c64f75e281f9c000", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "77","fffffffffffffffffffc0000000000000000000000000000","00000000000000000000000000000000","8dfd999be5d0cfa35732c0ddc88ff5a5", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "78","fffffffffffffffffffe0000000000000000000000000000","00000000000000000000000000000000","02647c76a300c3173b841487eb2bae9f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "79","ffffffffffffffffffff0000000000000000000000000000","00000000000000000000000000000000","172df8b02f04b53adab028b4e01acd87", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "80","ffffffffffffffffffff8000000000000000000000000000","00000000000000000000000000000000","054b3bf4998aeb05afd87ec536533a36", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "81","ffffffffffffffffffffc000000000000000000000000000","00000000000000000000000000000000","3783f7bf44c97f065258a666cae03020", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "82","ffffffffffffffffffffe000000000000000000000000000","00000000000000000000000000000000","aad4c8a63f80954104de7b92cede1be1", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "83","fffffffffffffffffffff000000000000000000000000000","00000000000000000000000000000000","cbfe61810fd5467ccdacb75800f3ac07", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "84","fffffffffffffffffffff800000000000000000000000000","00000000000000000000000000000000","830d8a2590f7d8e1b55a737f4af45f34", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "85","fffffffffffffffffffffc00000000000000000000000000","00000000000000000000000000000000","fffcd4683f858058e74314671d43fa2c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "86","fffffffffffffffffffffe00000000000000000000000000","00000000000000000000000000000000","523d0babbb82f46ebc9e70b1cd41ddd0", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "87","ffffffffffffffffffffff00000000000000000000000000","00000000000000000000000000000000","344aab37080d7486f7d542a309e53eed", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "88","ffffffffffffffffffffff80000000000000000000000000","00000000000000000000000000000000","56c5609d0906b23ab9caca816f5dbebd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "89","ffffffffffffffffffffffc0000000000000000000000000","00000000000000000000000000000000","7026026eedd91adc6d831cdf9894bdc6", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "90","ffffffffffffffffffffffe0000000000000000000000000","00000000000000000000000000000000","88330baa4f2b618fc9d9b021bf503d5a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "91","fffffffffffffffffffffff0000000000000000000000000","00000000000000000000000000000000","fc9e0ea22480b0bac935c8a8ebefcdcf", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "92","fffffffffffffffffffffff8000000000000000000000000","00000000000000000000000000000000","29ca779f398fb04f867da7e8a44756cb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "93","fffffffffffffffffffffffc000000000000000000000000","00000000000000000000000000000000","51f89c42985786bfc43c6df8ada36832", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "94","fffffffffffffffffffffffe000000000000000000000000","00000000000000000000000000000000","6ac1de5fb8f21d874e91c53b560c50e3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "95","ffffffffffffffffffffffff000000000000000000000000","00000000000000000000000000000000","03aa9058490eda306001a8a9f48d0ca7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "96","ffffffffffffffffffffffff800000000000000000000000","00000000000000000000000000000000","e34ec71d6128d4871865d617c30b37e3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "97","ffffffffffffffffffffffffc00000000000000000000000","00000000000000000000000000000000","14be1c535b17cabd0c4d93529d69bf47", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "98","ffffffffffffffffffffffffe00000000000000000000000","00000000000000000000000000000000","c9ef67756507beec9dd3862883478044", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "99","fffffffffffffffffffffffff00000000000000000000000","00000000000000000000000000000000","40e231fa5a5948ce2134e92fc0664d4b", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "100","fffffffffffffffffffffffff80000000000000000000000","00000000000000000000000000000000","03194b8e5dda5530d0c678c0b48f5d92", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "101","fffffffffffffffffffffffffc0000000000000000000000","00000000000000000000000000000000","90bd086f237cc4fd99f4d76bde6b4826", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "102","fffffffffffffffffffffffffe0000000000000000000000","00000000000000000000000000000000","19259761ca17130d6ed86d57cd7951ee", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "103","ffffffffffffffffffffffffff0000000000000000000000","00000000000000000000000000000000","d7cbb3f34b9b450f24b0e8518e54da6d", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "104","ffffffffffffffffffffffffff8000000000000000000000","00000000000000000000000000000000","725b9caebe9f7f417f4068d0d2ee20b3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "105","ffffffffffffffffffffffffffc000000000000000000000","00000000000000000000000000000000","9d924b934a90ce1fd39b8a9794f82672", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "106","ffffffffffffffffffffffffffe000000000000000000000","00000000000000000000000000000000","c50562bf094526a91c5bc63c0c224995", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "107","fffffffffffffffffffffffffff000000000000000000000","00000000000000000000000000000000","d2f11805046743bd74f57188d9188df7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "108","fffffffffffffffffffffffffff800000000000000000000","00000000000000000000000000000000","8dd274bd0f1b58ae345d9e7233f9b8f3", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "109","fffffffffffffffffffffffffffc00000000000000000000","00000000000000000000000000000000","9d6bdc8f4ce5feb0f3bed2e4b9a9bb0b", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "110","fffffffffffffffffffffffffffe00000000000000000000","00000000000000000000000000000000","fd5548bcf3f42565f7efa94562528d46", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "111","ffffffffffffffffffffffffffff00000000000000000000","00000000000000000000000000000000","d2ccaebd3a4c3e80b063748131ba4a71", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "112","ffffffffffffffffffffffffffff80000000000000000000","00000000000000000000000000000000","e03cb23d9e11c9d93f117e9c0a91b576", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "113","ffffffffffffffffffffffffffffc0000000000000000000","00000000000000000000000000000000","78f933a2081ac1db84f69d10f4523fe0", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "114","ffffffffffffffffffffffffffffe0000000000000000000","00000000000000000000000000000000","4061f7412ed320de0edc8851c2e2436f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "115","fffffffffffffffffffffffffffff0000000000000000000","00000000000000000000000000000000","9064ba1cd04ce6bab98474330814b4d4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "116","fffffffffffffffffffffffffffff8000000000000000000","00000000000000000000000000000000","48391bffb9cfff80ac238c886ef0a461", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "117","fffffffffffffffffffffffffffffc000000000000000000","00000000000000000000000000000000","b8d2a67df5a999fdbf93edd0343296c9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "118","fffffffffffffffffffffffffffffe000000000000000000","00000000000000000000000000000000","aaca7367396b69a221bd632bea386eec", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "119","ffffffffffffffffffffffffffffff000000000000000000","00000000000000000000000000000000","a80fd5020dfe65f5f16293ec92c6fd89", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "120","ffffffffffffffffffffffffffffff800000000000000000","00000000000000000000000000000000","2162995b8217a67f1abc342e146406f8", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "121","ffffffffffffffffffffffffffffffc00000000000000000","00000000000000000000000000000000","c6a6164b7a60bae4e986ffac28dfadd9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "122","ffffffffffffffffffffffffffffffe00000000000000000","00000000000000000000000000000000","64e0d7f900e3d9c83e4b8f96717b2146", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "123","fffffffffffffffffffffffffffffff00000000000000000","00000000000000000000000000000000","1ad2561de8c1232f5d8dbab4739b6cbb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "124","fffffffffffffffffffffffffffffff80000000000000000","00000000000000000000000000000000","279689e9a557f58b1c3bf40c97a90964", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "125","fffffffffffffffffffffffffffffffc0000000000000000","00000000000000000000000000000000","c4637e4a5e6377f9cc5a8638045de029", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "126","fffffffffffffffffffffffffffffffe0000000000000000","00000000000000000000000000000000","492e607e5aea4688594b45f3aee3df90", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "127","ffffffffffffffffffffffffffffffff0000000000000000","00000000000000000000000000000000","e8c4e4381feec74054954c05b777a00a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "128","ffffffffffffffffffffffffffffffff8000000000000000","00000000000000000000000000000000","91549514605f38246c9b724ad839f01d", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "129","ffffffffffffffffffffffffffffffffc000000000000000","00000000000000000000000000000000","74b24e3b6fefe40a4f9ef7ac6e44d76a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "130","ffffffffffffffffffffffffffffffffe000000000000000","00000000000000000000000000000000","2437a683dc5d4b52abb4a123a8df86c6", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "131","fffffffffffffffffffffffffffffffff000000000000000","00000000000000000000000000000000","bb2852c891c5947d2ed44032c421b85f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "132","fffffffffffffffffffffffffffffffff800000000000000","00000000000000000000000000000000","1b9f5fbd5e8a4264c0a85b80409afa5e", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "133","fffffffffffffffffffffffffffffffffc00000000000000","00000000000000000000000000000000","30dab809f85a917fe924733f424ac589", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "134","fffffffffffffffffffffffffffffffffe00000000000000","00000000000000000000000000000000","eaef5c1f8d605192646695ceadc65f32", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "135","ffffffffffffffffffffffffffffffffff00000000000000","00000000000000000000000000000000","b8aa90040b4c15a12316b78e0f9586fc", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "136","ffffffffffffffffffffffffffffffffff80000000000000","00000000000000000000000000000000","97fac8297ceaabc87d454350601e0673", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "137","ffffffffffffffffffffffffffffffffffc0000000000000","00000000000000000000000000000000","9b47ef567ac28dfe488492f157e2b2e0", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "138","ffffffffffffffffffffffffffffffffffe0000000000000","00000000000000000000000000000000","1b8426027ddb962b5c5ba7eb8bc9ab63", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "139","fffffffffffffffffffffffffffffffffff0000000000000","00000000000000000000000000000000","e917fc77e71992a12dbe4c18068bec82", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "140","fffffffffffffffffffffffffffffffffff8000000000000","00000000000000000000000000000000","dceebbc98840f8ae6daf76573b7e56f4", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "141","fffffffffffffffffffffffffffffffffffc000000000000","00000000000000000000000000000000","4e11a9f74205125b61e0aee047eca20d", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "142","fffffffffffffffffffffffffffffffffffe000000000000","00000000000000000000000000000000","f60467f55a1f17eab88e800120cbc284", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "143","ffffffffffffffffffffffffffffffffffff000000000000","00000000000000000000000000000000","d436649f600b449ee276530f0cd83c11", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "144","ffffffffffffffffffffffffffffffffffff800000000000","00000000000000000000000000000000","3bc0e3656a9e3ac7cd378a737f53b637", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "145","ffffffffffffffffffffffffffffffffffffc00000000000","00000000000000000000000000000000","6bacae63d33b928aa8380f8d54d88c17", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "146","ffffffffffffffffffffffffffffffffffffe00000000000","00000000000000000000000000000000","8935ffbc75ae6251bf8e859f085adcb9", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "147","fffffffffffffffffffffffffffffffffffff00000000000","00000000000000000000000000000000","93dc4970fe35f67747cb0562c06d875a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "148","fffffffffffffffffffffffffffffffffffff80000000000","00000000000000000000000000000000","14f9df858975851797ba604fb0d16cc7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "149","fffffffffffffffffffffffffffffffffffffc0000000000","00000000000000000000000000000000","02ea0c98dca10b38c21b3b14e8d1b71f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "150","fffffffffffffffffffffffffffffffffffffe0000000000","00000000000000000000000000000000","8f091b1b5b0749b2adc803e63dda9b72", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "151","ffffffffffffffffffffffffffffffffffffff0000000000","00000000000000000000000000000000","05b389e3322c6da08384345a4137fd08", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "152","ffffffffffffffffffffffffffffffffffffff8000000000","00000000000000000000000000000000","381308c438f35b399f10ad71b05027d8", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "153","ffffffffffffffffffffffffffffffffffffffc000000000","00000000000000000000000000000000","68c230fcfa9279c3409fc423e2acbe04", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "154","ffffffffffffffffffffffffffffffffffffffe000000000","00000000000000000000000000000000","1c84a475acb011f3f59f4f46b76274c0", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "155","fffffffffffffffffffffffffffffffffffffff000000000","00000000000000000000000000000000","45119b68cb3f8399ee60066b5611a4d7", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "156","fffffffffffffffffffffffffffffffffffffff800000000","00000000000000000000000000000000","9423762f527a4060ffca312dcca22a16", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "157","fffffffffffffffffffffffffffffffffffffffc00000000","00000000000000000000000000000000","f361a2745a33f056a5ac6ace2f08e344", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "158","fffffffffffffffffffffffffffffffffffffffe00000000","00000000000000000000000000000000","5ef145766eca849f5d011536a6557fdb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "159","ffffffffffffffffffffffffffffffffffffffff00000000","00000000000000000000000000000000","c9af27b2c89c9b4cf4a0c4106ac80318", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "160","ffffffffffffffffffffffffffffffffffffffff80000000","00000000000000000000000000000000","fb9c4f16c621f4eab7e9ac1d7551dd57", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "161","ffffffffffffffffffffffffffffffffffffffffc0000000","00000000000000000000000000000000","138e06fba466fa70854d8c2e524cffb2", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "162","ffffffffffffffffffffffffffffffffffffffffe0000000","00000000000000000000000000000000","fb4bc78b225070773f04c40466d4e90c", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "163","fffffffffffffffffffffffffffffffffffffffff0000000","00000000000000000000000000000000","8b2cbff1ed0150feda8a4799be94551f", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "164","fffffffffffffffffffffffffffffffffffffffff8000000","00000000000000000000000000000000","08b30d7b3f27962709a36bcadfb974bd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "165","fffffffffffffffffffffffffffffffffffffffffc000000","00000000000000000000000000000000","fdf6d32e044d77adcf37fb97ac213326", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "166","fffffffffffffffffffffffffffffffffffffffffe000000","00000000000000000000000000000000","93cb284ecdcfd781a8afe32077949e88", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "167","ffffffffffffffffffffffffffffffffffffffffff000000","00000000000000000000000000000000","7b017bb02ec87b2b94c96e40a26fc71a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "168","ffffffffffffffffffffffffffffffffffffffffff800000","00000000000000000000000000000000","c5c038b6990664ab08a3aaa5df9f3266", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "169","ffffffffffffffffffffffffffffffffffffffffffc00000","00000000000000000000000000000000","4b7020be37fab6259b2a27f4ec551576", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "170","ffffffffffffffffffffffffffffffffffffffffffe00000","00000000000000000000000000000000","60136703374f64e860b48ce31f930716", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "171","fffffffffffffffffffffffffffffffffffffffffff00000","00000000000000000000000000000000","8d63a269b14d506ccc401ab8a9f1b591", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "172","fffffffffffffffffffffffffffffffffffffffffff80000","00000000000000000000000000000000","d317f81dc6aa454aee4bd4a5a5cff4bd", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "173","fffffffffffffffffffffffffffffffffffffffffffc0000","00000000000000000000000000000000","dddececd5354f04d530d76ed884246eb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "174","fffffffffffffffffffffffffffffffffffffffffffe0000","00000000000000000000000000000000","41c5205cc8fd8eda9a3cffd2518f365a", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "175","ffffffffffffffffffffffffffffffffffffffffffff0000","00000000000000000000000000000000","cf42fb474293d96eca9db1b37b1ba676", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "176","ffffffffffffffffffffffffffffffffffffffffffff8000","00000000000000000000000000000000","a231692607169b4ecdead5cd3b10db3e", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "177","ffffffffffffffffffffffffffffffffffffffffffffc000","00000000000000000000000000000000","ace4b91c9c669e77e7acacd19859ed49", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "178","ffffffffffffffffffffffffffffffffffffffffffffe000","00000000000000000000000000000000","75db7cfd4a7b2b62ab78a48f3ddaf4af", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "179","fffffffffffffffffffffffffffffffffffffffffffff000","00000000000000000000000000000000","c1faba2d46e259cf480d7c38e4572a58", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "180","fffffffffffffffffffffffffffffffffffffffffffff800","00000000000000000000000000000000","241c45bc6ae16dee6eb7bea128701582", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "181","fffffffffffffffffffffffffffffffffffffffffffffc00","00000000000000000000000000000000","8fd03057cf1364420c2b78069a3e2502", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "182","fffffffffffffffffffffffffffffffffffffffffffffe00","00000000000000000000000000000000","ddb505e6cc1384cbaec1df90b80beb20", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "183","ffffffffffffffffffffffffffffffffffffffffffffff00","00000000000000000000000000000000","5674a3bed27bf4bd3622f9f5fe208306", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "184","ffffffffffffffffffffffffffffffffffffffffffffff80","00000000000000000000000000000000","b687f26a89cfbfbb8e5eeac54055315e", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "185","ffffffffffffffffffffffffffffffffffffffffffffffc0","00000000000000000000000000000000","0547dd32d3b29ab6a4caeb606c5b6f78", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "186","ffffffffffffffffffffffffffffffffffffffffffffffe0","00000000000000000000000000000000","186861f8bc5386d31fb77f720c3226e6", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "187","fffffffffffffffffffffffffffffffffffffffffffffff0","00000000000000000000000000000000","eacf1e6c4224efb38900b185ab1dfd42", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "188","fffffffffffffffffffffffffffffffffffffffffffffff8","00000000000000000000000000000000","d241aab05a42d319de81d874f5c7b90d", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "189","fffffffffffffffffffffffffffffffffffffffffffffffc","00000000000000000000000000000000","5eb9bc759e2ad8d2140a6c762ae9e1ab", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "190","fffffffffffffffffffffffffffffffffffffffffffffffe","00000000000000000000000000000000","018596e15e78e2c064159defce5f3085", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "191","ffffffffffffffffffffffffffffffffffffffffffffffff","00000000000000000000000000000000","dd8a493514231cbf56eccee4c40889fb", false);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "0","800000000000000000000000000000000000000000000000","de885dc87f5a92594082d02cc1e1b42c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "1","c00000000000000000000000000000000000000000000000","132b074e80f2a597bf5febd8ea5da55e","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "2","e00000000000000000000000000000000000000000000000","6eccedf8de592c22fb81347b79f2db1f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "3","f00000000000000000000000000000000000000000000000","180b09f267c45145db2f826c2582d35c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "4","f80000000000000000000000000000000000000000000000","edd807ef7652d7eb0e13c8b5e15b3bc0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "5","fc0000000000000000000000000000000000000000000000","9978bcf8dd8fd72241223ad24b31b8a4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "6","fe0000000000000000000000000000000000000000000000","5310f654343e8f27e12c83a48d24ff81","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "7","ff0000000000000000000000000000000000000000000000","833f71258d53036b02952c76c744f5a1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "8","ff8000000000000000000000000000000000000000000000","eba83ff200cff9318a92f8691a06b09f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "9","ffc000000000000000000000000000000000000000000000","ff620ccbe9f3292abdf2176b09f04eba","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "10","ffe000000000000000000000000000000000000000000000","7ababc4b3f516c9aafb35f4140b548f9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "11","fff000000000000000000000000000000000000000000000","aa187824d9c4582b0916493ecbde8c57","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "12","fff800000000000000000000000000000000000000000000","1c0ad553177fd5ea1092c9d626a29dc4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "13","fffc00000000000000000000000000000000000000000000","a5dc46c37261194124ecaebd680408ec","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "14","fffe00000000000000000000000000000000000000000000","e4f2f2ae23e9b10bacfa58601531ba54","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "15","ffff00000000000000000000000000000000000000000000","b7d67cf1a1e91e8ff3a57a172c7bf412","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "16","ffff80000000000000000000000000000000000000000000","26706be06967884e847d137128ce47b3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "17","ffffc0000000000000000000000000000000000000000000","b2f8b409b0585909aad3a7b5a219072a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "18","ffffe0000000000000000000000000000000000000000000","5e4b7bff0290c78344c54a23b722cd20","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "19","fffff0000000000000000000000000000000000000000000","07093657552d4414227ce161e9ebf7dd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "20","fffff8000000000000000000000000000000000000000000","e1af1e7d8bc225ed4dffb771ecbb9e67","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "21","fffffc000000000000000000000000000000000000000000","ef6555253635d8432156cfd9c11b145a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "22","fffffe000000000000000000000000000000000000000000","fb4035074a5d4260c90cbd6da6c3fceb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "23","ffffff000000000000000000000000000000000000000000","446ee416f9ad1c103eb0cc96751c88e1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "24","ffffff800000000000000000000000000000000000000000","198ae2a4637ac0a7890a8fd1485445c9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "25","ffffffc00000000000000000000000000000000000000000","562012ec8faded0825fb2fa70ab30cbd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "26","ffffffe00000000000000000000000000000000000000000","cc8a64b46b5d88bf7f247d4dbaf38f05","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "27","fffffff00000000000000000000000000000000000000000","a168253762e2cc81b42d1e5001762699","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "28","fffffff80000000000000000000000000000000000000000","1b41f83b38ce5032c6cd7af98cf62061","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "29","fffffffc0000000000000000000000000000000000000000","61a89990cd1411750d5fb0dc988447d4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "30","fffffffe0000000000000000000000000000000000000000","b5accc8ed629edf8c68a539183b1ea82","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "31","ffffffff0000000000000000000000000000000000000000","b16fa71f846b81a13f361c43a851f290","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "32","ffffffff8000000000000000000000000000000000000000","4fad6efdff5975aee7692234bcd54488","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "33","ffffffffc000000000000000000000000000000000000000","ebfdb05a783d03082dfe5fdd80a00b17","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "34","ffffffffe000000000000000000000000000000000000000","eb81b584766997af6ba5529d3bdd8609","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "35","fffffffff000000000000000000000000000000000000000","0cf4ff4f49c8a0ca060c443499e29313","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "36","fffffffff800000000000000000000000000000000000000","cc4ba8a8e029f8b26d8afff9df133bb6","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "37","fffffffffc00000000000000000000000000000000000000","fefebf64360f38e4e63558f0ffc550c3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "38","fffffffffe00000000000000000000000000000000000000","12ad98cbf725137d6a8108c2bed99322","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "39","ffffffffff00000000000000000000000000000000000000","6afaa996226198b3e2610413ce1b3f78","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "40","ffffffffff80000000000000000000000000000000000000","2a8ce6747a7e39367828e290848502d9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "41","ffffffffffc0000000000000000000000000000000000000","223736e8b8f89ca1e37b6deab40facf1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "42","ffffffffffe0000000000000000000000000000000000000","c0f797e50418b95fa6013333917a9480","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "43","fffffffffff0000000000000000000000000000000000000","a758de37c2ece2a02c73c01fedc9a132","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "44","fffffffffff8000000000000000000000000000000000000","3a9b87ae77bae706803966c66c73adbd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "45","fffffffffffc000000000000000000000000000000000000","d365ab8df8ffd782e358121a4a4fc541","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "46","fffffffffffe000000000000000000000000000000000000","c8dcd9e6f75e6c36c8daee0466f0ed74","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "47","ffffffffffff000000000000000000000000000000000000","c79a637beb1c0304f14014c037e736dd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "48","ffffffffffff800000000000000000000000000000000000","105f0a25e84ac930d996281a5f954dd9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "49","ffffffffffffc00000000000000000000000000000000000","42e4074b2927973e8d17ffa92f7fe615","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "50","ffffffffffffe00000000000000000000000000000000000","4fe2a9d2c1824449c69e3e0398f12963","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "51","fffffffffffff00000000000000000000000000000000000","b7f29c1e1f62847a15253b28a1e9d712","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "52","fffffffffffff80000000000000000000000000000000000","36ed5d29b903f31e8983ef8b0a2bf990","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "53","fffffffffffffc0000000000000000000000000000000000","27b8070270810f9d023f9dd7ff3b4aa2","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "54","fffffffffffffe0000000000000000000000000000000000","94d46e155c1228f61d1a0db4815ecc4b","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "55","ffffffffffffff0000000000000000000000000000000000","ca6108d1d98071428eeceef1714b96dd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "56","ffffffffffffff8000000000000000000000000000000000","dc5b25b71b6296cf73dd2cdcac2f70b1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "57","ffffffffffffffc000000000000000000000000000000000","44aba95e8a06a2d9d3530d2677878c80","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "58","ffffffffffffffe000000000000000000000000000000000","a570d20e89b467e8f5176061b81dd396","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "59","fffffffffffffff000000000000000000000000000000000","758f4467a5d8f1e7307dc30b34e404f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "60","fffffffffffffff800000000000000000000000000000000","bcea28e9071b5a2302970ff352451bc5","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "61","fffffffffffffffc00000000000000000000000000000000","7523c00bc177d331ad312e09c9015c1c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "62","fffffffffffffffe00000000000000000000000000000000","ccac61e3183747b3f5836da21a1bc4f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "63","ffffffffffffffff00000000000000000000000000000000","707b075791878880b44189d3522b8c30","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "64","ffffffffffffffff80000000000000000000000000000000","7132d0c0e4a07593cf12ebb12be7688c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "65","ffffffffffffffffc0000000000000000000000000000000","effbac1644deb0c784275fe56e19ead3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "66","ffffffffffffffffe0000000000000000000000000000000","a005063f30f4228b374e2459738f26bb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "67","fffffffffffffffff0000000000000000000000000000000","29975b5f48bb68fcbbc7cea93b452ed7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "68","fffffffffffffffff8000000000000000000000000000000","cf3f2576e2afedc74bb1ca7eeec1c0e7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "69","fffffffffffffffffc000000000000000000000000000000","07c403f5f966e0e3d9f296d6226dca28","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "70","fffffffffffffffffe000000000000000000000000000000","c8c20908249ab4a34d6dd0a31327ff1a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "71","ffffffffffffffffff000000000000000000000000000000","c0541329ecb6159ab23b7fc5e6a21bca","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "72","ffffffffffffffffff800000000000000000000000000000","7aa1acf1a2ed9ba72bc6deb31d88b863","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "73","ffffffffffffffffffc00000000000000000000000000000","808bd8eddabb6f3bf0d5a8a27be1fe8a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "74","ffffffffffffffffffe00000000000000000000000000000","273c7d7685e14ec66bbb96b8f05b6ddd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "75","fffffffffffffffffff00000000000000000000000000000","32752eefc8c2a93f91b6e73eb07cca6e","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "76","fffffffffffffffffff80000000000000000000000000000","d893e7d62f6ce502c64f75e281f9c000","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "77","fffffffffffffffffffc0000000000000000000000000000","8dfd999be5d0cfa35732c0ddc88ff5a5","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "78","fffffffffffffffffffe0000000000000000000000000000","02647c76a300c3173b841487eb2bae9f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "79","ffffffffffffffffffff0000000000000000000000000000","172df8b02f04b53adab028b4e01acd87","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "80","ffffffffffffffffffff8000000000000000000000000000","054b3bf4998aeb05afd87ec536533a36","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "81","ffffffffffffffffffffc000000000000000000000000000","3783f7bf44c97f065258a666cae03020","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "82","ffffffffffffffffffffe000000000000000000000000000","aad4c8a63f80954104de7b92cede1be1","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "83","fffffffffffffffffffff000000000000000000000000000","cbfe61810fd5467ccdacb75800f3ac07","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "84","fffffffffffffffffffff800000000000000000000000000","830d8a2590f7d8e1b55a737f4af45f34","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "85","fffffffffffffffffffffc00000000000000000000000000","fffcd4683f858058e74314671d43fa2c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "86","fffffffffffffffffffffe00000000000000000000000000","523d0babbb82f46ebc9e70b1cd41ddd0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "87","ffffffffffffffffffffff00000000000000000000000000","344aab37080d7486f7d542a309e53eed","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "88","ffffffffffffffffffffff80000000000000000000000000","56c5609d0906b23ab9caca816f5dbebd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "89","ffffffffffffffffffffffc0000000000000000000000000","7026026eedd91adc6d831cdf9894bdc6","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "90","ffffffffffffffffffffffe0000000000000000000000000","88330baa4f2b618fc9d9b021bf503d5a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "91","fffffffffffffffffffffff0000000000000000000000000","fc9e0ea22480b0bac935c8a8ebefcdcf","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "92","fffffffffffffffffffffff8000000000000000000000000","29ca779f398fb04f867da7e8a44756cb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "93","fffffffffffffffffffffffc000000000000000000000000","51f89c42985786bfc43c6df8ada36832","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "94","fffffffffffffffffffffffe000000000000000000000000","6ac1de5fb8f21d874e91c53b560c50e3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "95","ffffffffffffffffffffffff000000000000000000000000","03aa9058490eda306001a8a9f48d0ca7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "96","ffffffffffffffffffffffff800000000000000000000000","e34ec71d6128d4871865d617c30b37e3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "97","ffffffffffffffffffffffffc00000000000000000000000","14be1c535b17cabd0c4d93529d69bf47","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "98","ffffffffffffffffffffffffe00000000000000000000000","c9ef67756507beec9dd3862883478044","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "99","fffffffffffffffffffffffff00000000000000000000000","40e231fa5a5948ce2134e92fc0664d4b","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "100","fffffffffffffffffffffffff80000000000000000000000","03194b8e5dda5530d0c678c0b48f5d92","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "101","fffffffffffffffffffffffffc0000000000000000000000","90bd086f237cc4fd99f4d76bde6b4826","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "102","fffffffffffffffffffffffffe0000000000000000000000","19259761ca17130d6ed86d57cd7951ee","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "103","ffffffffffffffffffffffffff0000000000000000000000","d7cbb3f34b9b450f24b0e8518e54da6d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "104","ffffffffffffffffffffffffff8000000000000000000000","725b9caebe9f7f417f4068d0d2ee20b3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "105","ffffffffffffffffffffffffffc000000000000000000000","9d924b934a90ce1fd39b8a9794f82672","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "106","ffffffffffffffffffffffffffe000000000000000000000","c50562bf094526a91c5bc63c0c224995","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "107","fffffffffffffffffffffffffff000000000000000000000","d2f11805046743bd74f57188d9188df7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "108","fffffffffffffffffffffffffff800000000000000000000","8dd274bd0f1b58ae345d9e7233f9b8f3","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "109","fffffffffffffffffffffffffffc00000000000000000000","9d6bdc8f4ce5feb0f3bed2e4b9a9bb0b","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "110","fffffffffffffffffffffffffffe00000000000000000000","fd5548bcf3f42565f7efa94562528d46","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "111","ffffffffffffffffffffffffffff00000000000000000000","d2ccaebd3a4c3e80b063748131ba4a71","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "112","ffffffffffffffffffffffffffff80000000000000000000","e03cb23d9e11c9d93f117e9c0a91b576","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "113","ffffffffffffffffffffffffffffc0000000000000000000","78f933a2081ac1db84f69d10f4523fe0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "114","ffffffffffffffffffffffffffffe0000000000000000000","4061f7412ed320de0edc8851c2e2436f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "115","fffffffffffffffffffffffffffff0000000000000000000","9064ba1cd04ce6bab98474330814b4d4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "116","fffffffffffffffffffffffffffff8000000000000000000","48391bffb9cfff80ac238c886ef0a461","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "117","fffffffffffffffffffffffffffffc000000000000000000","b8d2a67df5a999fdbf93edd0343296c9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "118","fffffffffffffffffffffffffffffe000000000000000000","aaca7367396b69a221bd632bea386eec","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "119","ffffffffffffffffffffffffffffff000000000000000000","a80fd5020dfe65f5f16293ec92c6fd89","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "120","ffffffffffffffffffffffffffffff800000000000000000","2162995b8217a67f1abc342e146406f8","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "121","ffffffffffffffffffffffffffffffc00000000000000000","c6a6164b7a60bae4e986ffac28dfadd9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "122","ffffffffffffffffffffffffffffffe00000000000000000","64e0d7f900e3d9c83e4b8f96717b2146","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "123","fffffffffffffffffffffffffffffff00000000000000000","1ad2561de8c1232f5d8dbab4739b6cbb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "124","fffffffffffffffffffffffffffffff80000000000000000","279689e9a557f58b1c3bf40c97a90964","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "125","fffffffffffffffffffffffffffffffc0000000000000000","c4637e4a5e6377f9cc5a8638045de029","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "126","fffffffffffffffffffffffffffffffe0000000000000000","492e607e5aea4688594b45f3aee3df90","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "127","ffffffffffffffffffffffffffffffff0000000000000000","e8c4e4381feec74054954c05b777a00a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "128","ffffffffffffffffffffffffffffffff8000000000000000","91549514605f38246c9b724ad839f01d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "129","ffffffffffffffffffffffffffffffffc000000000000000","74b24e3b6fefe40a4f9ef7ac6e44d76a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "130","ffffffffffffffffffffffffffffffffe000000000000000","2437a683dc5d4b52abb4a123a8df86c6","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "131","fffffffffffffffffffffffffffffffff000000000000000","bb2852c891c5947d2ed44032c421b85f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "132","fffffffffffffffffffffffffffffffff800000000000000","1b9f5fbd5e8a4264c0a85b80409afa5e","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "133","fffffffffffffffffffffffffffffffffc00000000000000","30dab809f85a917fe924733f424ac589","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "134","fffffffffffffffffffffffffffffffffe00000000000000","eaef5c1f8d605192646695ceadc65f32","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "135","ffffffffffffffffffffffffffffffffff00000000000000","b8aa90040b4c15a12316b78e0f9586fc","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "136","ffffffffffffffffffffffffffffffffff80000000000000","97fac8297ceaabc87d454350601e0673","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "137","ffffffffffffffffffffffffffffffffffc0000000000000","9b47ef567ac28dfe488492f157e2b2e0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "138","ffffffffffffffffffffffffffffffffffe0000000000000","1b8426027ddb962b5c5ba7eb8bc9ab63","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "139","fffffffffffffffffffffffffffffffffff0000000000000","e917fc77e71992a12dbe4c18068bec82","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "140","fffffffffffffffffffffffffffffffffff8000000000000","dceebbc98840f8ae6daf76573b7e56f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "141","fffffffffffffffffffffffffffffffffffc000000000000","4e11a9f74205125b61e0aee047eca20d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "142","fffffffffffffffffffffffffffffffffffe000000000000","f60467f55a1f17eab88e800120cbc284","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "143","ffffffffffffffffffffffffffffffffffff000000000000","d436649f600b449ee276530f0cd83c11","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "144","ffffffffffffffffffffffffffffffffffff800000000000","3bc0e3656a9e3ac7cd378a737f53b637","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "145","ffffffffffffffffffffffffffffffffffffc00000000000","6bacae63d33b928aa8380f8d54d88c17","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "146","ffffffffffffffffffffffffffffffffffffe00000000000","8935ffbc75ae6251bf8e859f085adcb9","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "147","fffffffffffffffffffffffffffffffffffff00000000000","93dc4970fe35f67747cb0562c06d875a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "148","fffffffffffffffffffffffffffffffffffff80000000000","14f9df858975851797ba604fb0d16cc7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "149","fffffffffffffffffffffffffffffffffffffc0000000000","02ea0c98dca10b38c21b3b14e8d1b71f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "150","fffffffffffffffffffffffffffffffffffffe0000000000","8f091b1b5b0749b2adc803e63dda9b72","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "151","ffffffffffffffffffffffffffffffffffffff0000000000","05b389e3322c6da08384345a4137fd08","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "152","ffffffffffffffffffffffffffffffffffffff8000000000","381308c438f35b399f10ad71b05027d8","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "153","ffffffffffffffffffffffffffffffffffffffc000000000","68c230fcfa9279c3409fc423e2acbe04","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "154","ffffffffffffffffffffffffffffffffffffffe000000000","1c84a475acb011f3f59f4f46b76274c0","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "155","fffffffffffffffffffffffffffffffffffffff000000000","45119b68cb3f8399ee60066b5611a4d7","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "156","fffffffffffffffffffffffffffffffffffffff800000000","9423762f527a4060ffca312dcca22a16","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "157","fffffffffffffffffffffffffffffffffffffffc00000000","f361a2745a33f056a5ac6ace2f08e344","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "158","fffffffffffffffffffffffffffffffffffffffe00000000","5ef145766eca849f5d011536a6557fdb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "159","ffffffffffffffffffffffffffffffffffffffff00000000","c9af27b2c89c9b4cf4a0c4106ac80318","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "160","ffffffffffffffffffffffffffffffffffffffff80000000","fb9c4f16c621f4eab7e9ac1d7551dd57","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "161","ffffffffffffffffffffffffffffffffffffffffc0000000","138e06fba466fa70854d8c2e524cffb2","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "162","ffffffffffffffffffffffffffffffffffffffffe0000000","fb4bc78b225070773f04c40466d4e90c","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "163","fffffffffffffffffffffffffffffffffffffffff0000000","8b2cbff1ed0150feda8a4799be94551f","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "164","fffffffffffffffffffffffffffffffffffffffff8000000","08b30d7b3f27962709a36bcadfb974bd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "165","fffffffffffffffffffffffffffffffffffffffffc000000","fdf6d32e044d77adcf37fb97ac213326","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "166","fffffffffffffffffffffffffffffffffffffffffe000000","93cb284ecdcfd781a8afe32077949e88","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "167","ffffffffffffffffffffffffffffffffffffffffff000000","7b017bb02ec87b2b94c96e40a26fc71a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "168","ffffffffffffffffffffffffffffffffffffffffff800000","c5c038b6990664ab08a3aaa5df9f3266","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "169","ffffffffffffffffffffffffffffffffffffffffffc00000","4b7020be37fab6259b2a27f4ec551576","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "170","ffffffffffffffffffffffffffffffffffffffffffe00000","60136703374f64e860b48ce31f930716","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "171","fffffffffffffffffffffffffffffffffffffffffff00000","8d63a269b14d506ccc401ab8a9f1b591","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "172","fffffffffffffffffffffffffffffffffffffffffff80000","d317f81dc6aa454aee4bd4a5a5cff4bd","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "173","fffffffffffffffffffffffffffffffffffffffffffc0000","dddececd5354f04d530d76ed884246eb","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "174","fffffffffffffffffffffffffffffffffffffffffffe0000","41c5205cc8fd8eda9a3cffd2518f365a","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "175","ffffffffffffffffffffffffffffffffffffffffffff0000","cf42fb474293d96eca9db1b37b1ba676","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "176","ffffffffffffffffffffffffffffffffffffffffffff8000","a231692607169b4ecdead5cd3b10db3e","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "177","ffffffffffffffffffffffffffffffffffffffffffffc000","ace4b91c9c669e77e7acacd19859ed49","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "178","ffffffffffffffffffffffffffffffffffffffffffffe000","75db7cfd4a7b2b62ab78a48f3ddaf4af","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "179","fffffffffffffffffffffffffffffffffffffffffffff000","c1faba2d46e259cf480d7c38e4572a58","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "180","fffffffffffffffffffffffffffffffffffffffffffff800","241c45bc6ae16dee6eb7bea128701582","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "181","fffffffffffffffffffffffffffffffffffffffffffffc00","8fd03057cf1364420c2b78069a3e2502","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "182","fffffffffffffffffffffffffffffffffffffffffffffe00","ddb505e6cc1384cbaec1df90b80beb20","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "183","ffffffffffffffffffffffffffffffffffffffffffffff00","5674a3bed27bf4bd3622f9f5fe208306","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "184","ffffffffffffffffffffffffffffffffffffffffffffff80","b687f26a89cfbfbb8e5eeac54055315e","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "185","ffffffffffffffffffffffffffffffffffffffffffffffc0","0547dd32d3b29ab6a4caeb606c5b6f78","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "186","ffffffffffffffffffffffffffffffffffffffffffffffe0","186861f8bc5386d31fb77f720c3226e6","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "187","fffffffffffffffffffffffffffffffffffffffffffffff0","eacf1e6c4224efb38900b185ab1dfd42","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "188","fffffffffffffffffffffffffffffffffffffffffffffff8","d241aab05a42d319de81d874f5c7b90d","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "189","fffffffffffffffffffffffffffffffffffffffffffffffc","5eb9bc759e2ad8d2140a6c762ae9e1ab","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "190","fffffffffffffffffffffffffffffffffffffffffffffffe","018596e15e78e2c064159defce5f3085","00000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarKey192.rsp", "191","ffffffffffffffffffffffffffffffffffffffffffffffff","dd8a493514231cbf56eccee4c40889fb","00000000000000000000000000000000", true);
}

static void
aes_test_vartxt_192(void)
{
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "0","000000000000000000000000000000000000000000000000","80000000000000000000000000000000","6cd02513e8d4dc986b4afe087a60bd0c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "1","000000000000000000000000000000000000000000000000","c0000000000000000000000000000000","2ce1f8b7e30627c1c4519eada44bc436", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "2","000000000000000000000000000000000000000000000000","e0000000000000000000000000000000","9946b5f87af446f5796c1fee63a2da24", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "3","000000000000000000000000000000000000000000000000","f0000000000000000000000000000000","2a560364ce529efc21788779568d5555", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "4","000000000000000000000000000000000000000000000000","f8000000000000000000000000000000","35c1471837af446153bce55d5ba72a0a", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "5","000000000000000000000000000000000000000000000000","fc000000000000000000000000000000","ce60bc52386234f158f84341e534cd9e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "6","000000000000000000000000000000000000000000000000","fe000000000000000000000000000000","8c7c27ff32bcf8dc2dc57c90c2903961", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "7","000000000000000000000000000000000000000000000000","ff000000000000000000000000000000","32bb6a7ec84499e166f936003d55a5bb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "8","000000000000000000000000000000000000000000000000","ff800000000000000000000000000000","a5c772e5c62631ef660ee1d5877f6d1b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "9","000000000000000000000000000000000000000000000000","ffc00000000000000000000000000000","030d7e5b64f380a7e4ea5387b5cd7f49", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "10","000000000000000000000000000000000000000000000000","ffe00000000000000000000000000000","0dc9a2610037009b698f11bb7e86c83e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "11","000000000000000000000000000000000000000000000000","fff00000000000000000000000000000","0046612c766d1840c226364f1fa7ed72", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "12","000000000000000000000000000000000000000000000000","fff80000000000000000000000000000","4880c7e08f27befe78590743c05e698b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "13","000000000000000000000000000000000000000000000000","fffc0000000000000000000000000000","2520ce829a26577f0f4822c4ecc87401", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "14","000000000000000000000000000000000000000000000000","fffe0000000000000000000000000000","8765e8acc169758319cb46dc7bcf3dca", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "15","000000000000000000000000000000000000000000000000","ffff0000000000000000000000000000","e98f4ba4f073df4baa116d011dc24a28", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "16","000000000000000000000000000000000000000000000000","ffff8000000000000000000000000000","f378f68c5dbf59e211b3a659a7317d94", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "17","000000000000000000000000000000000000000000000000","ffffc000000000000000000000000000","283d3b069d8eb9fb432d74b96ca762b4", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "18","000000000000000000000000000000000000000000000000","ffffe000000000000000000000000000","a7e1842e8a87861c221a500883245c51", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "19","000000000000000000000000000000000000000000000000","fffff000000000000000000000000000","77aa270471881be070fb52c7067ce732", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "20","000000000000000000000000000000000000000000000000","fffff800000000000000000000000000","01b0f476d484f43f1aeb6efa9361a8ac", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "21","000000000000000000000000000000000000000000000000","fffffc00000000000000000000000000","1c3a94f1c052c55c2d8359aff2163b4f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "22","000000000000000000000000000000000000000000000000","fffffe00000000000000000000000000","e8a067b604d5373d8b0f2e05a03b341b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "23","000000000000000000000000000000000000000000000000","ffffff00000000000000000000000000","a7876ec87f5a09bfea42c77da30fd50e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "24","000000000000000000000000000000000000000000000000","ffffff80000000000000000000000000","0cf3e9d3a42be5b854ca65b13f35f48d", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "25","000000000000000000000000000000000000000000000000","ffffffc0000000000000000000000000","6c62f6bbcab7c3e821c9290f08892dda", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "26","000000000000000000000000000000000000000000000000","ffffffe0000000000000000000000000","7f5e05bd2068738196fee79ace7e3aec", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "27","000000000000000000000000000000000000000000000000","fffffff0000000000000000000000000","440e0d733255cda92fb46e842fe58054", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "28","000000000000000000000000000000000000000000000000","fffffff8000000000000000000000000","aa5d5b1c4ea1b7a22e5583ac2e9ed8a7", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "29","000000000000000000000000000000000000000000000000","fffffffc000000000000000000000000","77e537e89e8491e8662aae3bc809421d", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "30","000000000000000000000000000000000000000000000000","fffffffe000000000000000000000000","997dd3e9f1598bfa73f75973f7e93b76", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "31","000000000000000000000000000000000000000000000000","ffffffff000000000000000000000000","1b38d4f7452afefcb7fc721244e4b72e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "32","000000000000000000000000000000000000000000000000","ffffffff800000000000000000000000","0be2b18252e774dda30cdda02c6906e3", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "33","000000000000000000000000000000000000000000000000","ffffffffc00000000000000000000000","d2695e59c20361d82652d7d58b6f11b2", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "34","000000000000000000000000000000000000000000000000","ffffffffe00000000000000000000000","902d88d13eae52089abd6143cfe394e9", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "35","000000000000000000000000000000000000000000000000","fffffffff00000000000000000000000","d49bceb3b823fedd602c305345734bd2", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "36","000000000000000000000000000000000000000000000000","fffffffff80000000000000000000000","707b1dbb0ffa40ef7d95def421233fae", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "37","000000000000000000000000000000000000000000000000","fffffffffc0000000000000000000000","7ca0c1d93356d9eb8aa952084d75f913", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "38","000000000000000000000000000000000000000000000000","fffffffffe0000000000000000000000","f2cbf9cb186e270dd7bdb0c28febc57d", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "39","000000000000000000000000000000000000000000000000","ffffffffff0000000000000000000000","c94337c37c4e790ab45780bd9c3674a0", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "40","000000000000000000000000000000000000000000000000","ffffffffff8000000000000000000000","8e3558c135252fb9c9f367ed609467a1", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "41","000000000000000000000000000000000000000000000000","ffffffffffc000000000000000000000","1b72eeaee4899b443914e5b3a57fba92", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "42","000000000000000000000000000000000000000000000000","ffffffffffe000000000000000000000","011865f91bc56868d051e52c9efd59b7", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "43","000000000000000000000000000000000000000000000000","fffffffffff000000000000000000000","e4771318ad7a63dd680f6e583b7747ea", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "44","000000000000000000000000000000000000000000000000","fffffffffff800000000000000000000","61e3d194088dc8d97e9e6db37457eac5", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "45","000000000000000000000000000000000000000000000000","fffffffffffc00000000000000000000","36ff1ec9ccfbc349e5d356d063693ad6", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "46","000000000000000000000000000000000000000000000000","fffffffffffe00000000000000000000","3cc9e9a9be8cc3f6fb2ea24088e9bb19", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "47","000000000000000000000000000000000000000000000000","ffffffffffff00000000000000000000","1ee5ab003dc8722e74905d9a8fe3d350", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "48","000000000000000000000000000000000000000000000000","ffffffffffff80000000000000000000","245339319584b0a412412869d6c2eada", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "49","000000000000000000000000000000000000000000000000","ffffffffffffc0000000000000000000","7bd496918115d14ed5380852716c8814", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "50","000000000000000000000000000000000000000000000000","ffffffffffffe0000000000000000000","273ab2f2b4a366a57d582a339313c8b1", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "51","000000000000000000000000000000000000000000000000","fffffffffffff0000000000000000000","113365a9ffbe3b0ca61e98507554168b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "52","000000000000000000000000000000000000000000000000","fffffffffffff8000000000000000000","afa99c997ac478a0dea4119c9e45f8b1", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "53","000000000000000000000000000000000000000000000000","fffffffffffffc000000000000000000","9216309a7842430b83ffb98638011512", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "54","000000000000000000000000000000000000000000000000","fffffffffffffe000000000000000000","62abc792288258492a7cb45145f4b759", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "55","000000000000000000000000000000000000000000000000","ffffffffffffff000000000000000000","534923c169d504d7519c15d30e756c50", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "56","000000000000000000000000000000000000000000000000","ffffffffffffff800000000000000000","fa75e05bcdc7e00c273fa33f6ee441d2", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "57","000000000000000000000000000000000000000000000000","ffffffffffffffc00000000000000000","7d350fa6057080f1086a56b17ec240db", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "58","000000000000000000000000000000000000000000000000","ffffffffffffffe00000000000000000","f34e4a6324ea4a5c39a661c8fe5ada8f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "59","000000000000000000000000000000000000000000000000","fffffffffffffff00000000000000000","0882a16f44088d42447a29ac090ec17e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "60","000000000000000000000000000000000000000000000000","fffffffffffffff80000000000000000","3a3c15bfc11a9537c130687004e136ee", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "61","000000000000000000000000000000000000000000000000","fffffffffffffffc0000000000000000","22c0a7678dc6d8cf5c8a6d5a9960767c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "62","000000000000000000000000000000000000000000000000","fffffffffffffffe0000000000000000","b46b09809d68b9a456432a79bdc2e38c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "63","000000000000000000000000000000000000000000000000","ffffffffffffffff0000000000000000","93baaffb35fbe739c17c6ac22eecf18f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "64","000000000000000000000000000000000000000000000000","ffffffffffffffff8000000000000000","c8aa80a7850675bc007c46df06b49868", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "65","000000000000000000000000000000000000000000000000","ffffffffffffffffc000000000000000","12c6f3877af421a918a84b775858021d", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "66","000000000000000000000000000000000000000000000000","ffffffffffffffffe000000000000000","33f123282c5d633924f7d5ba3f3cab11", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "67","000000000000000000000000000000000000000000000000","fffffffffffffffff000000000000000","a8f161002733e93ca4527d22c1a0c5bb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "68","000000000000000000000000000000000000000000000000","fffffffffffffffff800000000000000","b72f70ebf3e3fda23f508eec76b42c02", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "69","000000000000000000000000000000000000000000000000","fffffffffffffffffc00000000000000","6a9d965e6274143f25afdcfc88ffd77c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "70","000000000000000000000000000000000000000000000000","fffffffffffffffffe00000000000000","a0c74fd0b9361764ce91c5200b095357", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "71","000000000000000000000000000000000000000000000000","ffffffffffffffffff00000000000000","091d1fdc2bd2c346cd5046a8c6209146", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "72","000000000000000000000000000000000000000000000000","ffffffffffffffffff80000000000000","e2a37580116cfb71856254496ab0aca8", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "73","000000000000000000000000000000000000000000000000","ffffffffffffffffffc0000000000000","e0b3a00785917c7efc9adba322813571", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "74","000000000000000000000000000000000000000000000000","ffffffffffffffffffe0000000000000","733d41f4727b5ef0df4af4cf3cffa0cb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "75","000000000000000000000000000000000000000000000000","fffffffffffffffffff0000000000000","a99ebb030260826f981ad3e64490aa4f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "76","000000000000000000000000000000000000000000000000","fffffffffffffffffff8000000000000","73f34c7d3eae5e80082c1647524308ee", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "77","000000000000000000000000000000000000000000000000","fffffffffffffffffffc000000000000","40ebd5ad082345b7a2097ccd3464da02", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "78","000000000000000000000000000000000000000000000000","fffffffffffffffffffe000000000000","7cc4ae9a424b2cec90c97153c2457ec5", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "79","000000000000000000000000000000000000000000000000","ffffffffffffffffffff000000000000","54d632d03aba0bd0f91877ebdd4d09cb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "80","000000000000000000000000000000000000000000000000","ffffffffffffffffffff800000000000","d3427be7e4d27cd54f5fe37b03cf0897", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "81","000000000000000000000000000000000000000000000000","ffffffffffffffffffffc00000000000","b2099795e88cc158fd75ea133d7e7fbe", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "82","000000000000000000000000000000000000000000000000","ffffffffffffffffffffe00000000000","a6cae46fb6fadfe7a2c302a34242817b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "83","000000000000000000000000000000000000000000000000","fffffffffffffffffffff00000000000","026a7024d6a902e0b3ffccbaa910cc3f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "84","000000000000000000000000000000000000000000000000","fffffffffffffffffffff80000000000","156f07767a85a4312321f63968338a01", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "85","000000000000000000000000000000000000000000000000","fffffffffffffffffffffc0000000000","15eec9ebf42b9ca76897d2cd6c5a12e2", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "86","000000000000000000000000000000000000000000000000","fffffffffffffffffffffe0000000000","db0d3a6fdcc13f915e2b302ceeb70fd8", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "87","000000000000000000000000000000000000000000000000","ffffffffffffffffffffff0000000000","71dbf37e87a2e34d15b20e8f10e48924", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "88","000000000000000000000000000000000000000000000000","ffffffffffffffffffffff8000000000","c745c451e96ff3c045e4367c833e3b54", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "89","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffc000000000","340da09c2dd11c3b679d08ccd27dd595", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "90","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffe000000000","8279f7c0c2a03ee660c6d392db025d18", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "91","000000000000000000000000000000000000000000000000","fffffffffffffffffffffff000000000","a4b2c7d8eba531ff47c5041a55fbd1ec", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "92","000000000000000000000000000000000000000000000000","fffffffffffffffffffffff800000000","74569a2ca5a7bd5131ce8dc7cbfbf72f", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "93","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffc00000000","3713da0c0219b63454035613b5a403dd", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "94","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffe00000000","8827551ddcc9df23fa72a3de4e9f0b07", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "95","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffff00000000","2e3febfd625bfcd0a2c06eb460da1732", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "96","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffff80000000","ee82e6ba488156f76496311da6941deb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "97","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffc0000000","4770446f01d1f391256e85a1b30d89d3", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "98","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffe0000000","af04b68f104f21ef2afb4767cf74143c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "99","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffff0000000","cf3579a9ba38c8e43653173e14f3a4c6", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "100","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffff8000000","b3bba904f4953e09b54800af2f62e7d4", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "101","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffc000000","fc4249656e14b29eb9c44829b4c59a46", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "102","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffe000000","9b31568febe81cfc2e65af1c86d1a308", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "103","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffff000000","9ca09c25f273a766db98a480ce8dfedc", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "104","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffff800000","b909925786f34c3c92d971883c9fbedf", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "105","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffc00000","82647f1332fe570a9d4d92b2ee771d3b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "106","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffe00000","3604a7e80832b3a99954bca6f5b9f501", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "107","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffff00000","884607b128c5de3ab39a529a1ef51bef", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "108","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffff80000","670cfa093d1dbdb2317041404102435e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "109","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffc0000","7a867195f3ce8769cbd336502fbb5130", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "110","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffe0000","52efcf64c72b2f7ca5b3c836b1078c15", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "111","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffff0000","4019250f6eefb2ac5ccbcae044e75c7e", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "112","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffff8000","022c4f6f5a017d292785627667ddef24", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "113","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffc000","e9c21078a2eb7e03250f71000fa9e3ed", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "114","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffe000","a13eaeeb9cd391da4e2b09490b3e7fad", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "115","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffff000","c958a171dca1d4ed53e1af1d380803a9", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "116","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffff800","21442e07a110667f2583eaeeee44dc8c", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "117","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffc00","59bbb353cf1dd867a6e33737af655e99", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "118","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffe00","43cd3b25375d0ce41087ff9fe2829639", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "119","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffff00","6b98b17e80d1118e3516bd768b285a84", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "120","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffff80","ae47ed3676ca0c08deea02d95b81db58", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "121","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffc0","34ec40dc20413795ed53628ea748720b", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "122","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffe0","4dc68163f8e9835473253542c8a65d46", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "123","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffff0","2aabb999f43693175af65c6c612c46fb", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "124","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffff8","e01f94499dac3547515c5b1d756f0f58", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "125","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffffc","9d12435a46480ce00ea349f71799df9a", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "126","000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffffe","cef41d16d266bdfe46938ad7884cc0cf", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "127","000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffff","b13db4da1f718bc6904797c82bcf2d32", false);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "0","000000000000000000000000000000000000000000000000","6cd02513e8d4dc986b4afe087a60bd0c","80000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "1","000000000000000000000000000000000000000000000000","2ce1f8b7e30627c1c4519eada44bc436","c0000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "2","000000000000000000000000000000000000000000000000","9946b5f87af446f5796c1fee63a2da24","e0000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "3","000000000000000000000000000000000000000000000000","2a560364ce529efc21788779568d5555","f0000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "4","000000000000000000000000000000000000000000000000","35c1471837af446153bce55d5ba72a0a","f8000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "5","000000000000000000000000000000000000000000000000","ce60bc52386234f158f84341e534cd9e","fc000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "6","000000000000000000000000000000000000000000000000","8c7c27ff32bcf8dc2dc57c90c2903961","fe000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "7","000000000000000000000000000000000000000000000000","32bb6a7ec84499e166f936003d55a5bb","ff000000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "8","000000000000000000000000000000000000000000000000","a5c772e5c62631ef660ee1d5877f6d1b","ff800000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "9","000000000000000000000000000000000000000000000000","030d7e5b64f380a7e4ea5387b5cd7f49","ffc00000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "10","000000000000000000000000000000000000000000000000","0dc9a2610037009b698f11bb7e86c83e","ffe00000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "11","000000000000000000000000000000000000000000000000","0046612c766d1840c226364f1fa7ed72","fff00000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "12","000000000000000000000000000000000000000000000000","4880c7e08f27befe78590743c05e698b","fff80000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "13","000000000000000000000000000000000000000000000000","2520ce829a26577f0f4822c4ecc87401","fffc0000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "14","000000000000000000000000000000000000000000000000","8765e8acc169758319cb46dc7bcf3dca","fffe0000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "15","000000000000000000000000000000000000000000000000","e98f4ba4f073df4baa116d011dc24a28","ffff0000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "16","000000000000000000000000000000000000000000000000","f378f68c5dbf59e211b3a659a7317d94","ffff8000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "17","000000000000000000000000000000000000000000000000","283d3b069d8eb9fb432d74b96ca762b4","ffffc000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "18","000000000000000000000000000000000000000000000000","a7e1842e8a87861c221a500883245c51","ffffe000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "19","000000000000000000000000000000000000000000000000","77aa270471881be070fb52c7067ce732","fffff000000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "20","000000000000000000000000000000000000000000000000","01b0f476d484f43f1aeb6efa9361a8ac","fffff800000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "21","000000000000000000000000000000000000000000000000","1c3a94f1c052c55c2d8359aff2163b4f","fffffc00000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "22","000000000000000000000000000000000000000000000000","e8a067b604d5373d8b0f2e05a03b341b","fffffe00000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "23","000000000000000000000000000000000000000000000000","a7876ec87f5a09bfea42c77da30fd50e","ffffff00000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "24","000000000000000000000000000000000000000000000000","0cf3e9d3a42be5b854ca65b13f35f48d","ffffff80000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "25","000000000000000000000000000000000000000000000000","6c62f6bbcab7c3e821c9290f08892dda","ffffffc0000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "26","000000000000000000000000000000000000000000000000","7f5e05bd2068738196fee79ace7e3aec","ffffffe0000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "27","000000000000000000000000000000000000000000000000","440e0d733255cda92fb46e842fe58054","fffffff0000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "28","000000000000000000000000000000000000000000000000","aa5d5b1c4ea1b7a22e5583ac2e9ed8a7","fffffff8000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "29","000000000000000000000000000000000000000000000000","77e537e89e8491e8662aae3bc809421d","fffffffc000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "30","000000000000000000000000000000000000000000000000","997dd3e9f1598bfa73f75973f7e93b76","fffffffe000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "31","000000000000000000000000000000000000000000000000","1b38d4f7452afefcb7fc721244e4b72e","ffffffff000000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "32","000000000000000000000000000000000000000000000000","0be2b18252e774dda30cdda02c6906e3","ffffffff800000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "33","000000000000000000000000000000000000000000000000","d2695e59c20361d82652d7d58b6f11b2","ffffffffc00000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "34","000000000000000000000000000000000000000000000000","902d88d13eae52089abd6143cfe394e9","ffffffffe00000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "35","000000000000000000000000000000000000000000000000","d49bceb3b823fedd602c305345734bd2","fffffffff00000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "36","000000000000000000000000000000000000000000000000","707b1dbb0ffa40ef7d95def421233fae","fffffffff80000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "37","000000000000000000000000000000000000000000000000","7ca0c1d93356d9eb8aa952084d75f913","fffffffffc0000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "38","000000000000000000000000000000000000000000000000","f2cbf9cb186e270dd7bdb0c28febc57d","fffffffffe0000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "39","000000000000000000000000000000000000000000000000","c94337c37c4e790ab45780bd9c3674a0","ffffffffff0000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "40","000000000000000000000000000000000000000000000000","8e3558c135252fb9c9f367ed609467a1","ffffffffff8000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "41","000000000000000000000000000000000000000000000000","1b72eeaee4899b443914e5b3a57fba92","ffffffffffc000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "42","000000000000000000000000000000000000000000000000","011865f91bc56868d051e52c9efd59b7","ffffffffffe000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "43","000000000000000000000000000000000000000000000000","e4771318ad7a63dd680f6e583b7747ea","fffffffffff000000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "44","000000000000000000000000000000000000000000000000","61e3d194088dc8d97e9e6db37457eac5","fffffffffff800000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "45","000000000000000000000000000000000000000000000000","36ff1ec9ccfbc349e5d356d063693ad6","fffffffffffc00000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "46","000000000000000000000000000000000000000000000000","3cc9e9a9be8cc3f6fb2ea24088e9bb19","fffffffffffe00000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "47","000000000000000000000000000000000000000000000000","1ee5ab003dc8722e74905d9a8fe3d350","ffffffffffff00000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "48","000000000000000000000000000000000000000000000000","245339319584b0a412412869d6c2eada","ffffffffffff80000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "49","000000000000000000000000000000000000000000000000","7bd496918115d14ed5380852716c8814","ffffffffffffc0000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "50","000000000000000000000000000000000000000000000000","273ab2f2b4a366a57d582a339313c8b1","ffffffffffffe0000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "51","000000000000000000000000000000000000000000000000","113365a9ffbe3b0ca61e98507554168b","fffffffffffff0000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "52","000000000000000000000000000000000000000000000000","afa99c997ac478a0dea4119c9e45f8b1","fffffffffffff8000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "53","000000000000000000000000000000000000000000000000","9216309a7842430b83ffb98638011512","fffffffffffffc000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "54","000000000000000000000000000000000000000000000000","62abc792288258492a7cb45145f4b759","fffffffffffffe000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "55","000000000000000000000000000000000000000000000000","534923c169d504d7519c15d30e756c50","ffffffffffffff000000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "56","000000000000000000000000000000000000000000000000","fa75e05bcdc7e00c273fa33f6ee441d2","ffffffffffffff800000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "57","000000000000000000000000000000000000000000000000","7d350fa6057080f1086a56b17ec240db","ffffffffffffffc00000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "58","000000000000000000000000000000000000000000000000","f34e4a6324ea4a5c39a661c8fe5ada8f","ffffffffffffffe00000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "59","000000000000000000000000000000000000000000000000","0882a16f44088d42447a29ac090ec17e","fffffffffffffff00000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "60","000000000000000000000000000000000000000000000000","3a3c15bfc11a9537c130687004e136ee","fffffffffffffff80000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "61","000000000000000000000000000000000000000000000000","22c0a7678dc6d8cf5c8a6d5a9960767c","fffffffffffffffc0000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "62","000000000000000000000000000000000000000000000000","b46b09809d68b9a456432a79bdc2e38c","fffffffffffffffe0000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "63","000000000000000000000000000000000000000000000000","93baaffb35fbe739c17c6ac22eecf18f","ffffffffffffffff0000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "64","000000000000000000000000000000000000000000000000","c8aa80a7850675bc007c46df06b49868","ffffffffffffffff8000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "65","000000000000000000000000000000000000000000000000","12c6f3877af421a918a84b775858021d","ffffffffffffffffc000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "66","000000000000000000000000000000000000000000000000","33f123282c5d633924f7d5ba3f3cab11","ffffffffffffffffe000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "67","000000000000000000000000000000000000000000000000","a8f161002733e93ca4527d22c1a0c5bb","fffffffffffffffff000000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "68","000000000000000000000000000000000000000000000000","b72f70ebf3e3fda23f508eec76b42c02","fffffffffffffffff800000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "69","000000000000000000000000000000000000000000000000","6a9d965e6274143f25afdcfc88ffd77c","fffffffffffffffffc00000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "70","000000000000000000000000000000000000000000000000","a0c74fd0b9361764ce91c5200b095357","fffffffffffffffffe00000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "71","000000000000000000000000000000000000000000000000","091d1fdc2bd2c346cd5046a8c6209146","ffffffffffffffffff00000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "72","000000000000000000000000000000000000000000000000","e2a37580116cfb71856254496ab0aca8","ffffffffffffffffff80000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "73","000000000000000000000000000000000000000000000000","e0b3a00785917c7efc9adba322813571","ffffffffffffffffffc0000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "74","000000000000000000000000000000000000000000000000","733d41f4727b5ef0df4af4cf3cffa0cb","ffffffffffffffffffe0000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "75","000000000000000000000000000000000000000000000000","a99ebb030260826f981ad3e64490aa4f","fffffffffffffffffff0000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "76","000000000000000000000000000000000000000000000000","73f34c7d3eae5e80082c1647524308ee","fffffffffffffffffff8000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "77","000000000000000000000000000000000000000000000000","40ebd5ad082345b7a2097ccd3464da02","fffffffffffffffffffc000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "78","000000000000000000000000000000000000000000000000","7cc4ae9a424b2cec90c97153c2457ec5","fffffffffffffffffffe000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "79","000000000000000000000000000000000000000000000000","54d632d03aba0bd0f91877ebdd4d09cb","ffffffffffffffffffff000000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "80","000000000000000000000000000000000000000000000000","d3427be7e4d27cd54f5fe37b03cf0897","ffffffffffffffffffff800000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "81","000000000000000000000000000000000000000000000000","b2099795e88cc158fd75ea133d7e7fbe","ffffffffffffffffffffc00000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "82","000000000000000000000000000000000000000000000000","a6cae46fb6fadfe7a2c302a34242817b","ffffffffffffffffffffe00000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "83","000000000000000000000000000000000000000000000000","026a7024d6a902e0b3ffccbaa910cc3f","fffffffffffffffffffff00000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "84","000000000000000000000000000000000000000000000000","156f07767a85a4312321f63968338a01","fffffffffffffffffffff80000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "85","000000000000000000000000000000000000000000000000","15eec9ebf42b9ca76897d2cd6c5a12e2","fffffffffffffffffffffc0000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "86","000000000000000000000000000000000000000000000000","db0d3a6fdcc13f915e2b302ceeb70fd8","fffffffffffffffffffffe0000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "87","000000000000000000000000000000000000000000000000","71dbf37e87a2e34d15b20e8f10e48924","ffffffffffffffffffffff0000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "88","000000000000000000000000000000000000000000000000","c745c451e96ff3c045e4367c833e3b54","ffffffffffffffffffffff8000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "89","000000000000000000000000000000000000000000000000","340da09c2dd11c3b679d08ccd27dd595","ffffffffffffffffffffffc000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "90","000000000000000000000000000000000000000000000000","8279f7c0c2a03ee660c6d392db025d18","ffffffffffffffffffffffe000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "91","000000000000000000000000000000000000000000000000","a4b2c7d8eba531ff47c5041a55fbd1ec","fffffffffffffffffffffff000000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "92","000000000000000000000000000000000000000000000000","74569a2ca5a7bd5131ce8dc7cbfbf72f","fffffffffffffffffffffff800000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "93","000000000000000000000000000000000000000000000000","3713da0c0219b63454035613b5a403dd","fffffffffffffffffffffffc00000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "94","000000000000000000000000000000000000000000000000","8827551ddcc9df23fa72a3de4e9f0b07","fffffffffffffffffffffffe00000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "95","000000000000000000000000000000000000000000000000","2e3febfd625bfcd0a2c06eb460da1732","ffffffffffffffffffffffff00000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "96","000000000000000000000000000000000000000000000000","ee82e6ba488156f76496311da6941deb","ffffffffffffffffffffffff80000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "97","000000000000000000000000000000000000000000000000","4770446f01d1f391256e85a1b30d89d3","ffffffffffffffffffffffffc0000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "98","000000000000000000000000000000000000000000000000","af04b68f104f21ef2afb4767cf74143c","ffffffffffffffffffffffffe0000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "99","000000000000000000000000000000000000000000000000","cf3579a9ba38c8e43653173e14f3a4c6","fffffffffffffffffffffffff0000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "100","000000000000000000000000000000000000000000000000","b3bba904f4953e09b54800af2f62e7d4","fffffffffffffffffffffffff8000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "101","000000000000000000000000000000000000000000000000","fc4249656e14b29eb9c44829b4c59a46","fffffffffffffffffffffffffc000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "102","000000000000000000000000000000000000000000000000","9b31568febe81cfc2e65af1c86d1a308","fffffffffffffffffffffffffe000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "103","000000000000000000000000000000000000000000000000","9ca09c25f273a766db98a480ce8dfedc","ffffffffffffffffffffffffff000000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "104","000000000000000000000000000000000000000000000000","b909925786f34c3c92d971883c9fbedf","ffffffffffffffffffffffffff800000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "105","000000000000000000000000000000000000000000000000","82647f1332fe570a9d4d92b2ee771d3b","ffffffffffffffffffffffffffc00000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "106","000000000000000000000000000000000000000000000000","3604a7e80832b3a99954bca6f5b9f501","ffffffffffffffffffffffffffe00000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "107","000000000000000000000000000000000000000000000000","884607b128c5de3ab39a529a1ef51bef","fffffffffffffffffffffffffff00000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "108","000000000000000000000000000000000000000000000000","670cfa093d1dbdb2317041404102435e","fffffffffffffffffffffffffff80000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "109","000000000000000000000000000000000000000000000000","7a867195f3ce8769cbd336502fbb5130","fffffffffffffffffffffffffffc0000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "110","000000000000000000000000000000000000000000000000","52efcf64c72b2f7ca5b3c836b1078c15","fffffffffffffffffffffffffffe0000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "111","000000000000000000000000000000000000000000000000","4019250f6eefb2ac5ccbcae044e75c7e","ffffffffffffffffffffffffffff0000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "112","000000000000000000000000000000000000000000000000","022c4f6f5a017d292785627667ddef24","ffffffffffffffffffffffffffff8000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "113","000000000000000000000000000000000000000000000000","e9c21078a2eb7e03250f71000fa9e3ed","ffffffffffffffffffffffffffffc000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "114","000000000000000000000000000000000000000000000000","a13eaeeb9cd391da4e2b09490b3e7fad","ffffffffffffffffffffffffffffe000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "115","000000000000000000000000000000000000000000000000","c958a171dca1d4ed53e1af1d380803a9","fffffffffffffffffffffffffffff000", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "116","000000000000000000000000000000000000000000000000","21442e07a110667f2583eaeeee44dc8c","fffffffffffffffffffffffffffff800", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "117","000000000000000000000000000000000000000000000000","59bbb353cf1dd867a6e33737af655e99","fffffffffffffffffffffffffffffc00", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "118","000000000000000000000000000000000000000000000000","43cd3b25375d0ce41087ff9fe2829639","fffffffffffffffffffffffffffffe00", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "119","000000000000000000000000000000000000000000000000","6b98b17e80d1118e3516bd768b285a84","ffffffffffffffffffffffffffffff00", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "120","000000000000000000000000000000000000000000000000","ae47ed3676ca0c08deea02d95b81db58","ffffffffffffffffffffffffffffff80", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "121","000000000000000000000000000000000000000000000000","34ec40dc20413795ed53628ea748720b","ffffffffffffffffffffffffffffffc0", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "122","000000000000000000000000000000000000000000000000","4dc68163f8e9835473253542c8a65d46","ffffffffffffffffffffffffffffffe0", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "123","000000000000000000000000000000000000000000000000","2aabb999f43693175af65c6c612c46fb","fffffffffffffffffffffffffffffff0", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "124","000000000000000000000000000000000000000000000000","e01f94499dac3547515c5b1d756f0f58","fffffffffffffffffffffffffffffff8", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "125","000000000000000000000000000000000000000000000000","9d12435a46480ce00ea349f71799df9a","fffffffffffffffffffffffffffffffc", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "126","000000000000000000000000000000000000000000000000","cef41d16d266bdfe46938ad7884cc0cf","fffffffffffffffffffffffffffffffe", true);
    aes_test(maid_aes_192, "ECBVarTxt192.rsp", "127","000000000000000000000000000000000000000000000000","b13db4da1f718bc6904797c82bcf2d32","ffffffffffffffffffffffffffffffff", true);
}

static void
aes_test_gfsbox_256(void)
{
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "0","0000000000000000000000000000000000000000000000000000000000000000","014730f80ac625fe84f026c60bfd547d","5c9d844ed46f9885085e5d6a4f94c7d7", false);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "1","0000000000000000000000000000000000000000000000000000000000000000","0b24af36193ce4665f2825d7b4749c98","a9ff75bd7cf6613d3731c77c3b6d0c04", false);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "2","0000000000000000000000000000000000000000000000000000000000000000","761c1fe41a18acf20d241650611d90f1","623a52fcea5d443e48d9181ab32c7421", false);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "3","0000000000000000000000000000000000000000000000000000000000000000","8a560769d605868ad80d819bdba03771","38f2c7ae10612415d27ca190d27da8b4", false);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "4","0000000000000000000000000000000000000000000000000000000000000000","91fbef2d15a97816060bee1feaa49afe","1bc704f1bce135ceb810341b216d7abe", false);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "0","0000000000000000000000000000000000000000000000000000000000000000","5c9d844ed46f9885085e5d6a4f94c7d7","014730f80ac625fe84f026c60bfd547d", true);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "1","0000000000000000000000000000000000000000000000000000000000000000","a9ff75bd7cf6613d3731c77c3b6d0c04","0b24af36193ce4665f2825d7b4749c98", true);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "2","0000000000000000000000000000000000000000000000000000000000000000","623a52fcea5d443e48d9181ab32c7421","761c1fe41a18acf20d241650611d90f1", true);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "3","0000000000000000000000000000000000000000000000000000000000000000","38f2c7ae10612415d27ca190d27da8b4","8a560769d605868ad80d819bdba03771", true);
    aes_test(maid_aes_256, "ECBGFSbox256.rsp", "4","0000000000000000000000000000000000000000000000000000000000000000","1bc704f1bce135ceb810341b216d7abe","91fbef2d15a97816060bee1feaa49afe", true);
}

static void
aes_test_keysbox_256(void)
{
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "0","c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558","00000000000000000000000000000000","46f2fb342d6f0ab477476fc501242c5f", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "1","28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64","00000000000000000000000000000000","4bf3b0a69aeb6657794f2901b1440ad4", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "2","c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c","00000000000000000000000000000000","352065272169abf9856843927d0674fd", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "3","984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627","00000000000000000000000000000000","4307456a9e67813b452e15fa8fffe398", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "4","b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f","00000000000000000000000000000000","4663446607354989477a5c6f0f007ef4", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "5","1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9","00000000000000000000000000000000","531c2c38344578b84d50b3c917bbb6e1", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "6","dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf","00000000000000000000000000000000","fc6aec906323480005c58e7e1ab004ad", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "7","f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9","00000000000000000000000000000000","a3944b95ca0b52043584ef02151926a8", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "8","797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e","00000000000000000000000000000000","a74289fe73a4c123ca189ea1e1b49ad5", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "9","6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707","00000000000000000000000000000000","b91d4ea4488644b56cf0812fa7fcf5fc", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "10","ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc","00000000000000000000000000000000","304f81ab61a80c2e743b94d5002a126b", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "11","13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887","00000000000000000000000000000000","649a71545378c783e368c9ade7114f6c", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "12","07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee","00000000000000000000000000000000","47cb030da2ab051dfc6c4bf6910d12bb", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "13","90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1","00000000000000000000000000000000","798c7c005dee432b2c8ea5dfa381ecc3", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "14","b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07","00000000000000000000000000000000","637c31dc2591a07636f646b72daabbe7", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "15","fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e","00000000000000000000000000000000","179a49c712154bbffbe6e7a84a18e220", false);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "0","c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558","46f2fb342d6f0ab477476fc501242c5f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "1","28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64","4bf3b0a69aeb6657794f2901b1440ad4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "2","c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c","352065272169abf9856843927d0674fd","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "3","984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627","4307456a9e67813b452e15fa8fffe398","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "4","b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f","4663446607354989477a5c6f0f007ef4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "5","1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9","531c2c38344578b84d50b3c917bbb6e1","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "6","dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf","fc6aec906323480005c58e7e1ab004ad","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "7","f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9","a3944b95ca0b52043584ef02151926a8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "8","797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e","a74289fe73a4c123ca189ea1e1b49ad5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "9","6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707","b91d4ea4488644b56cf0812fa7fcf5fc","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "10","ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc","304f81ab61a80c2e743b94d5002a126b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "11","13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887","649a71545378c783e368c9ade7114f6c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "12","07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee","47cb030da2ab051dfc6c4bf6910d12bb","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "13","90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1","798c7c005dee432b2c8ea5dfa381ecc3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "14","b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07","637c31dc2591a07636f646b72daabbe7","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBKeySbox256.rsp", "15","fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e","179a49c712154bbffbe6e7a84a18e220","00000000000000000000000000000000", true);
}

static void
aes_test_varkey_256(void)
{
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "0","8000000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","e35a6dcb19b201a01ebcfa8aa22b5759", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "1","c000000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","b29169cdcf2d83e838125a12ee6aa400", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "2","e000000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","d8f3a72fc3cdf74dfaf6c3e6b97b2fa6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "3","f000000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","1c777679d50037c79491a94da76a9a35", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "4","f800000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","9cf4893ecafa0a0247a898e040691559", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "5","fc00000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","8fbb413703735326310a269bd3aa94b2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "6","fe00000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","60e32246bed2b0e859e55c1cc6b26502", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "7","ff00000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","ec52a212f80a09df6317021bc2a9819e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "8","ff80000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","f23e5b600eb70dbccf6c0b1d9a68182c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "9","ffc0000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","a3f599d63a82a968c33fe26590745970", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "10","ffe0000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","d1ccb9b1337002cbac42c520b5d67722", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "11","fff0000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","cc111f6c37cf40a1159d00fb59fb0488", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "12","fff8000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","dc43b51ab609052372989a26e9cdd714", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "13","fffc000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","4dcede8da9e2578f39703d4433dc6459", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "14","fffe000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","1a4c1c263bbccfafc11782894685e3a8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "15","ffff000000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","937ad84880db50613423d6d527a2823d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "16","ffff800000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","610b71dfc688e150d8152c5b35ebc14d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "17","ffffc00000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","27ef2495dabf323885aab39c80f18d8b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "18","ffffe00000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","633cafea395bc03adae3a1e2068e4b4e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "19","fffff00000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","6e1b482b53761cf631819b749a6f3724", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "20","fffff80000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","976e6f851ab52c771998dbb2d71c75a9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "21","fffffc0000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","85f2ba84f8c307cf525e124c3e22e6cc", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "22","fffffe0000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","6bcca98bf6a835fa64955f72de4115fe", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "23","ffffff0000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","2c75e2d36eebd65411f14fd0eb1d2a06", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "24","ffffff8000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","bd49295006250ffca5100b6007a0eade", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "25","ffffffc000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","a190527d0ef7c70f459cd3940df316ec", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "26","ffffffe000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","bbd1097a62433f79449fa97d4ee80dbf", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "27","fffffff000000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","07058e408f5b99b0e0f061a1761b5b3b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "28","fffffff800000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","5fd1f13fa0f31e37fabde328f894eac2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "29","fffffffc00000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","fc4af7c948df26e2ef3e01c1ee5b8f6f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "30","fffffffe00000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","829fd7208fb92d44a074a677ee9861ac", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "31","ffffffff00000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","ad9fc613a703251b54c64a0e76431711", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "32","ffffffff80000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","33ac9eccc4cc75e2711618f80b1548e8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "33","ffffffffc0000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","2025c74b8ad8f4cda17ee2049c4c902d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "34","ffffffffe0000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","f85ca05fe528f1ce9b790166e8d551e7", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "35","fffffffff0000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","6f6238d8966048d4967154e0dad5a6c9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "36","fffffffff8000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","f2b21b4e7640a9b3346de8b82fb41e49", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "37","fffffffffc000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","f836f251ad1d11d49dc344628b1884e1", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "38","fffffffffe000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","077e9470ae7abea5a9769d49182628c3", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "39","ffffffffff000000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","e0dcc2d27fc9865633f85223cf0d611f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "40","ffffffffff800000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","be66cfea2fecd6bf0ec7b4352c99bcaa", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "41","ffffffffffc00000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","df31144f87a2ef523facdcf21a427804", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "42","ffffffffffe00000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","b5bb0f5629fb6aae5e1839a3c3625d63", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "43","fffffffffff00000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","3c9db3335306fe1ec612bdbfae6b6028", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "44","fffffffffff80000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","3dd5c34634a79d3cfcc8339760e6f5f4", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "45","fffffffffffc0000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","82bda118a3ed7af314fa2ccc5c07b761", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "46","fffffffffffe0000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","2937a64f7d4f46fe6fea3b349ec78e38", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "47","ffffffffffff0000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","225f068c28476605735ad671bb8f39f3", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "48","ffffffffffff8000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","ae682c5ecd71898e08942ac9aa89875c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "49","ffffffffffffc000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","5e031cb9d676c3022d7f26227e85c38f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "50","ffffffffffffe000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","a78463fb064db5d52bb64bfef64f2dda", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "51","fffffffffffff000000000000000000000000000000000000000000000000000","00000000000000000000000000000000","8aa9b75e784593876c53a00eae5af52b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "52","fffffffffffff800000000000000000000000000000000000000000000000000","00000000000000000000000000000000","3f84566df23da48af692722fe980573a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "53","fffffffffffffc00000000000000000000000000000000000000000000000000","00000000000000000000000000000000","31690b5ed41c7eb42a1e83270a7ff0e6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "54","fffffffffffffe00000000000000000000000000000000000000000000000000","00000000000000000000000000000000","77dd7702646d55f08365e477d3590eda", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "55","ffffffffffffff00000000000000000000000000000000000000000000000000","00000000000000000000000000000000","4c022ac62b3cb78d739cc67b3e20bb7e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "56","ffffffffffffff80000000000000000000000000000000000000000000000000","00000000000000000000000000000000","092fa137ce18b5dfe7906f550bb13370", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "57","ffffffffffffffc0000000000000000000000000000000000000000000000000","00000000000000000000000000000000","3e0cdadf2e68353c0027672c97144dd3", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "58","ffffffffffffffe0000000000000000000000000000000000000000000000000","00000000000000000000000000000000","d8c4b200b383fc1f2b2ea677618a1d27", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "59","fffffffffffffff0000000000000000000000000000000000000000000000000","00000000000000000000000000000000","11825f99b0e9bb3477c1c0713b015aac", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "60","fffffffffffffff8000000000000000000000000000000000000000000000000","00000000000000000000000000000000","f8b9fffb5c187f7ddc7ab10f4fb77576", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "61","fffffffffffffffc000000000000000000000000000000000000000000000000","00000000000000000000000000000000","ffb4e87a32b37d6f2c8328d3b5377802", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "62","fffffffffffffffe000000000000000000000000000000000000000000000000","00000000000000000000000000000000","d276c13a5d220f4da9224e74896391ce", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "63","ffffffffffffffff000000000000000000000000000000000000000000000000","00000000000000000000000000000000","94efe7a0e2e031e2536da01df799c927", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "64","ffffffffffffffff800000000000000000000000000000000000000000000000","00000000000000000000000000000000","8f8fd822680a85974e53a5a8eb9d38de", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "65","ffffffffffffffffc00000000000000000000000000000000000000000000000","00000000000000000000000000000000","e0f0a91b2e45f8cc37b7805a3042588d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "66","ffffffffffffffffe00000000000000000000000000000000000000000000000","00000000000000000000000000000000","597a6252255e46d6364dbeeda31e279c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "67","fffffffffffffffff00000000000000000000000000000000000000000000000","00000000000000000000000000000000","f51a0f694442b8f05571797fec7ee8bf", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "68","fffffffffffffffff80000000000000000000000000000000000000000000000","00000000000000000000000000000000","9ff071b165b5198a93dddeebc54d09b5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "69","fffffffffffffffffc0000000000000000000000000000000000000000000000","00000000000000000000000000000000","c20a19fd5758b0c4bc1a5df89cf73877", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "70","fffffffffffffffffe0000000000000000000000000000000000000000000000","00000000000000000000000000000000","97120166307119ca2280e9315668e96f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "71","ffffffffffffffffff0000000000000000000000000000000000000000000000","00000000000000000000000000000000","4b3b9f1e099c2a09dc091e90e4f18f0a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "72","ffffffffffffffffff8000000000000000000000000000000000000000000000","00000000000000000000000000000000","eb040b891d4b37f6851f7ec219cd3f6d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "73","ffffffffffffffffffc000000000000000000000000000000000000000000000","00000000000000000000000000000000","9f0fdec08b7fd79aa39535bea42db92a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "74","ffffffffffffffffffe000000000000000000000000000000000000000000000","00000000000000000000000000000000","2e70f168fc74bf911df240bcd2cef236", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "75","fffffffffffffffffff000000000000000000000000000000000000000000000","00000000000000000000000000000000","462ccd7f5fd1108dbc152f3cacad328b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "76","fffffffffffffffffff800000000000000000000000000000000000000000000","00000000000000000000000000000000","a4af534a7d0b643a01868785d86dfb95", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "77","fffffffffffffffffffc00000000000000000000000000000000000000000000","00000000000000000000000000000000","ab980296197e1a5022326c31da4bf6f3", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "78","fffffffffffffffffffe00000000000000000000000000000000000000000000","00000000000000000000000000000000","f97d57b3333b6281b07d486db2d4e20c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "79","ffffffffffffffffffff00000000000000000000000000000000000000000000","00000000000000000000000000000000","f33fa36720231afe4c759ade6bd62eb6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "80","ffffffffffffffffffff80000000000000000000000000000000000000000000","00000000000000000000000000000000","fdcfac0c02ca538343c68117e0a15938", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "81","ffffffffffffffffffffc0000000000000000000000000000000000000000000","00000000000000000000000000000000","ad4916f5ee5772be764fc027b8a6e539", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "82","ffffffffffffffffffffe0000000000000000000000000000000000000000000","00000000000000000000000000000000","2e16873e1678610d7e14c02d002ea845", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "83","fffffffffffffffffffff0000000000000000000000000000000000000000000","00000000000000000000000000000000","4e6e627c1acc51340053a8236d579576", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "84","fffffffffffffffffffff8000000000000000000000000000000000000000000","00000000000000000000000000000000","ab0c8410aeeead92feec1eb430d652cb", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "85","fffffffffffffffffffffc000000000000000000000000000000000000000000","00000000000000000000000000000000","e86f7e23e835e114977f60e1a592202e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "86","fffffffffffffffffffffe000000000000000000000000000000000000000000","00000000000000000000000000000000","e68ad5055a367041fade09d9a70a794b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "87","ffffffffffffffffffffff000000000000000000000000000000000000000000","00000000000000000000000000000000","0791823a3c666bb6162825e78606a7fe", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "88","ffffffffffffffffffffff800000000000000000000000000000000000000000","00000000000000000000000000000000","dcca366a9bf47b7b868b77e25c18a364", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "89","ffffffffffffffffffffffc00000000000000000000000000000000000000000","00000000000000000000000000000000","684c9efc237e4a442965f84bce20247a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "90","ffffffffffffffffffffffe00000000000000000000000000000000000000000","00000000000000000000000000000000","a858411ffbe63fdb9c8aa1bfaed67b52", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "91","fffffffffffffffffffffff00000000000000000000000000000000000000000","00000000000000000000000000000000","04bc3da2179c3015498b0e03910db5b8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "92","fffffffffffffffffffffff80000000000000000000000000000000000000000","00000000000000000000000000000000","40071eeab3f935dbc25d00841460260f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "93","fffffffffffffffffffffffc0000000000000000000000000000000000000000","00000000000000000000000000000000","0ebd7c30ed2016e08ba806ddb008bcc8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "94","fffffffffffffffffffffffe0000000000000000000000000000000000000000","00000000000000000000000000000000","15c6becf0f4cec7129cbd22d1a79b1b8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "95","ffffffffffffffffffffffff0000000000000000000000000000000000000000","00000000000000000000000000000000","0aeede5b91f721700e9e62edbf60b781", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "96","ffffffffffffffffffffffff8000000000000000000000000000000000000000","00000000000000000000000000000000","266581af0dcfbed1585e0a242c64b8df", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "97","ffffffffffffffffffffffffc000000000000000000000000000000000000000","00000000000000000000000000000000","6693dc911662ae473216ba22189a511a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "98","ffffffffffffffffffffffffe000000000000000000000000000000000000000","00000000000000000000000000000000","7606fa36d86473e6fb3a1bb0e2c0adf5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "99","fffffffffffffffffffffffff000000000000000000000000000000000000000","00000000000000000000000000000000","112078e9e11fbb78e26ffb8899e96b9a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "100","fffffffffffffffffffffffff800000000000000000000000000000000000000","00000000000000000000000000000000","40b264e921e9e4a82694589ef3798262", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "101","fffffffffffffffffffffffffc00000000000000000000000000000000000000","00000000000000000000000000000000","8d4595cb4fa7026715f55bd68e2882f9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "102","fffffffffffffffffffffffffe00000000000000000000000000000000000000","00000000000000000000000000000000","b588a302bdbc09197df1edae68926ed9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "103","ffffffffffffffffffffffffff00000000000000000000000000000000000000","00000000000000000000000000000000","33f7502390b8a4a221cfecd0666624ba", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "104","ffffffffffffffffffffffffff80000000000000000000000000000000000000","00000000000000000000000000000000","3d20253adbce3be2373767c4d822c566", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "105","ffffffffffffffffffffffffffc0000000000000000000000000000000000000","00000000000000000000000000000000","a42734a3929bf84cf0116c9856a3c18c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "106","ffffffffffffffffffffffffffe0000000000000000000000000000000000000","00000000000000000000000000000000","e3abc4939457422bb957da3c56938c6d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "107","fffffffffffffffffffffffffff0000000000000000000000000000000000000","00000000000000000000000000000000","972bdd2e7c525130fadc8f76fc6f4b3f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "108","fffffffffffffffffffffffffff8000000000000000000000000000000000000","00000000000000000000000000000000","84a83d7b94c699cbcb8a7d9b61f64093", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "109","fffffffffffffffffffffffffffc000000000000000000000000000000000000","00000000000000000000000000000000","ce61d63514aded03d43e6ebfc3a9001f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "110","fffffffffffffffffffffffffffe000000000000000000000000000000000000","00000000000000000000000000000000","6c839dd58eeae6b8a36af48ed63d2dc9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "111","ffffffffffffffffffffffffffff000000000000000000000000000000000000","00000000000000000000000000000000","cd5ece55b8da3bf622c4100df5de46f9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "112","ffffffffffffffffffffffffffff800000000000000000000000000000000000","00000000000000000000000000000000","3b6f46f40e0ac5fc0a9c1105f800f48d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "113","ffffffffffffffffffffffffffffc00000000000000000000000000000000000","00000000000000000000000000000000","ba26d47da3aeb028de4fb5b3a854a24b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "114","ffffffffffffffffffffffffffffe00000000000000000000000000000000000","00000000000000000000000000000000","87f53bf620d3677268445212904389d5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "115","fffffffffffffffffffffffffffff00000000000000000000000000000000000","00000000000000000000000000000000","10617d28b5e0f4605492b182a5d7f9f6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "116","fffffffffffffffffffffffffffff80000000000000000000000000000000000","00000000000000000000000000000000","9aaec4fabbf6fae2a71feff02e372b39", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "117","fffffffffffffffffffffffffffffc0000000000000000000000000000000000","00000000000000000000000000000000","3a90c62d88b5c42809abf782488ed130", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "118","fffffffffffffffffffffffffffffe0000000000000000000000000000000000","00000000000000000000000000000000","f1f1c5a40899e15772857ccb65c7a09a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "119","ffffffffffffffffffffffffffffff0000000000000000000000000000000000","00000000000000000000000000000000","190843d29b25a3897c692ce1dd81ee52", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "120","ffffffffffffffffffffffffffffff8000000000000000000000000000000000","00000000000000000000000000000000","a866bc65b6941d86e8420a7ffb0964db", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "121","ffffffffffffffffffffffffffffffc000000000000000000000000000000000","00000000000000000000000000000000","8193c6ff85225ced4255e92f6e078a14", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "122","ffffffffffffffffffffffffffffffe000000000000000000000000000000000","00000000000000000000000000000000","9661cb2424d7d4a380d547f9e7ec1cb9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "123","fffffffffffffffffffffffffffffff000000000000000000000000000000000","00000000000000000000000000000000","86f93d9ec08453a071e2e2877877a9c8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "124","fffffffffffffffffffffffffffffff800000000000000000000000000000000","00000000000000000000000000000000","27eefa80ce6a4a9d598e3fec365434d2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "125","fffffffffffffffffffffffffffffffc00000000000000000000000000000000","00000000000000000000000000000000","d62068444578e3ab39ce7ec95dd045dc", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "126","fffffffffffffffffffffffffffffffe00000000000000000000000000000000","00000000000000000000000000000000","b5f71d4dd9a71fe5d8bc8ba7e6ea3048", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "127","ffffffffffffffffffffffffffffffff00000000000000000000000000000000","00000000000000000000000000000000","6825a347ac479d4f9d95c5cb8d3fd7e9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "128","ffffffffffffffffffffffffffffffff80000000000000000000000000000000","00000000000000000000000000000000","e3714e94a5778955cc0346358e94783a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "129","ffffffffffffffffffffffffffffffffc0000000000000000000000000000000","00000000000000000000000000000000","d836b44bb29e0c7d89fa4b2d4b677d2a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "130","ffffffffffffffffffffffffffffffffe0000000000000000000000000000000","00000000000000000000000000000000","5d454b75021d76d4b84f873a8f877b92", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "131","fffffffffffffffffffffffffffffffff0000000000000000000000000000000","00000000000000000000000000000000","c3498f7eced2095314fc28115885b33f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "132","fffffffffffffffffffffffffffffffff8000000000000000000000000000000","00000000000000000000000000000000","6e668856539ad8e405bd123fe6c88530", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "133","fffffffffffffffffffffffffffffffffc000000000000000000000000000000","00000000000000000000000000000000","8680db7f3a87b8605543cfdbe6754076", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "134","fffffffffffffffffffffffffffffffffe000000000000000000000000000000","00000000000000000000000000000000","6c5d03b13069c3658b3179be91b0800c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "135","ffffffffffffffffffffffffffffffffff000000000000000000000000000000","00000000000000000000000000000000","ef1b384ac4d93eda00c92add0995ea5f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "136","ffffffffffffffffffffffffffffffffff800000000000000000000000000000","00000000000000000000000000000000","bf8115805471741bd5ad20a03944790f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "137","ffffffffffffffffffffffffffffffffffc00000000000000000000000000000","00000000000000000000000000000000","c64c24b6894b038b3c0d09b1df068b0b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "138","ffffffffffffffffffffffffffffffffffe00000000000000000000000000000","00000000000000000000000000000000","3967a10cffe27d0178545fbf6a40544b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "139","fffffffffffffffffffffffffffffffffff00000000000000000000000000000","00000000000000000000000000000000","7c85e9c95de1a9ec5a5363a8a053472d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "140","fffffffffffffffffffffffffffffffffff80000000000000000000000000000","00000000000000000000000000000000","a9eec03c8abec7ba68315c2c8c2316e0", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "141","fffffffffffffffffffffffffffffffffffc0000000000000000000000000000","00000000000000000000000000000000","cac8e414c2f388227ae14986fc983524", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "142","fffffffffffffffffffffffffffffffffffe0000000000000000000000000000","00000000000000000000000000000000","5d942b7f4622ce056c3ce3ce5f1dd9d6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "143","ffffffffffffffffffffffffffffffffffff0000000000000000000000000000","00000000000000000000000000000000","d240d648ce21a3020282c3f1b528a0b6", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "144","ffffffffffffffffffffffffffffffffffff8000000000000000000000000000","00000000000000000000000000000000","45d089c36d5c5a4efc689e3b0de10dd5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "145","ffffffffffffffffffffffffffffffffffffc000000000000000000000000000","00000000000000000000000000000000","b4da5df4becb5462e03a0ed00d295629", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "146","ffffffffffffffffffffffffffffffffffffe000000000000000000000000000","00000000000000000000000000000000","dcf4e129136c1a4b7a0f38935cc34b2b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "147","fffffffffffffffffffffffffffffffffffff000000000000000000000000000","00000000000000000000000000000000","d9a4c7618b0ce48a3d5aee1a1c0114c4", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "148","fffffffffffffffffffffffffffffffffffff800000000000000000000000000","00000000000000000000000000000000","ca352df025c65c7b0bf306fbee0f36ba", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "149","fffffffffffffffffffffffffffffffffffffc00000000000000000000000000","00000000000000000000000000000000","238aca23fd3409f38af63378ed2f5473", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "150","fffffffffffffffffffffffffffffffffffffe00000000000000000000000000","00000000000000000000000000000000","59836a0e06a79691b36667d5380d8188", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "151","ffffffffffffffffffffffffffffffffffffff00000000000000000000000000","00000000000000000000000000000000","33905080f7acf1cdae0a91fc3e85aee4", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "152","ffffffffffffffffffffffffffffffffffffff80000000000000000000000000","00000000000000000000000000000000","72c9e4646dbc3d6320fc6689d93e8833", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "153","ffffffffffffffffffffffffffffffffffffffc0000000000000000000000000","00000000000000000000000000000000","ba77413dea5925b7f5417ea47ff19f59", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "154","ffffffffffffffffffffffffffffffffffffffe0000000000000000000000000","00000000000000000000000000000000","6cae8129f843d86dc786a0fb1a184970", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "155","fffffffffffffffffffffffffffffffffffffff0000000000000000000000000","00000000000000000000000000000000","fcfefb534100796eebbd990206754e19", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "156","fffffffffffffffffffffffffffffffffffffff8000000000000000000000000","00000000000000000000000000000000","8c791d5fdddf470da04f3e6dc4a5b5b5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "157","fffffffffffffffffffffffffffffffffffffffc000000000000000000000000","00000000000000000000000000000000","c93bbdc07a4611ae4bb266ea5034a387", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "158","fffffffffffffffffffffffffffffffffffffffe000000000000000000000000","00000000000000000000000000000000","c102e38e489aa74762f3efc5bb23205a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "159","ffffffffffffffffffffffffffffffffffffffff000000000000000000000000","00000000000000000000000000000000","93201481665cbafc1fcc220bc545fb3d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "160","ffffffffffffffffffffffffffffffffffffffff800000000000000000000000","00000000000000000000000000000000","4960757ec6ce68cf195e454cfd0f32ca", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "161","ffffffffffffffffffffffffffffffffffffffffc00000000000000000000000","00000000000000000000000000000000","feec7ce6a6cbd07c043416737f1bbb33", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "162","ffffffffffffffffffffffffffffffffffffffffe00000000000000000000000","00000000000000000000000000000000","11c5413904487a805d70a8edd9c35527", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "163","fffffffffffffffffffffffffffffffffffffffff00000000000000000000000","00000000000000000000000000000000","347846b2b2e36f1f0324c86f7f1b98e2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "164","fffffffffffffffffffffffffffffffffffffffff80000000000000000000000","00000000000000000000000000000000","332eee1a0cbd19ca2d69b426894044f0", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "165","fffffffffffffffffffffffffffffffffffffffffc0000000000000000000000","00000000000000000000000000000000","866b5b3977ba6efa5128efbda9ff03cd", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "166","fffffffffffffffffffffffffffffffffffffffffe0000000000000000000000","00000000000000000000000000000000","cc1445ee94c0f08cdee5c344ecd1e233", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "167","ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000","00000000000000000000000000000000","be288319029363c2622feba4b05dfdfe", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "168","ffffffffffffffffffffffffffffffffffffffffff8000000000000000000000","00000000000000000000000000000000","cfd1875523f3cd21c395651e6ee15e56", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "169","ffffffffffffffffffffffffffffffffffffffffffc000000000000000000000","00000000000000000000000000000000","cb5a408657837c53bf16f9d8465dce19", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "170","ffffffffffffffffffffffffffffffffffffffffffe000000000000000000000","00000000000000000000000000000000","ca0bf42cb107f55ccff2fc09ee08ca15", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "171","fffffffffffffffffffffffffffffffffffffffffff000000000000000000000","00000000000000000000000000000000","fdd9bbb4a7dc2e4a23536a5880a2db67", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "172","fffffffffffffffffffffffffffffffffffffffffff800000000000000000000","00000000000000000000000000000000","ede447b362c484993dec9442a3b46aef", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "173","fffffffffffffffffffffffffffffffffffffffffffc00000000000000000000","00000000000000000000000000000000","10dffb05904bff7c4781df780ad26837", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "174","fffffffffffffffffffffffffffffffffffffffffffe00000000000000000000","00000000000000000000000000000000","c33bc13e8de88ac25232aa7496398783", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "175","ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000","00000000000000000000000000000000","ca359c70803a3b2a3d542e8781dea975", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "176","ffffffffffffffffffffffffffffffffffffffffffff80000000000000000000","00000000000000000000000000000000","bcc65b526f88d05b89ce8a52021fdb06", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "177","ffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000","00000000000000000000000000000000","db91a38855c8c4643851fbfb358b0109", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "178","ffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000","00000000000000000000000000000000","ca6e8893a114ae8e27d5ab03a5499610", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "179","fffffffffffffffffffffffffffffffffffffffffffff0000000000000000000","00000000000000000000000000000000","6629d2b8df97da728cdd8b1e7f945077", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "180","fffffffffffffffffffffffffffffffffffffffffffff8000000000000000000","00000000000000000000000000000000","4570a5a18cfc0dd582f1d88d5c9a1720", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "181","fffffffffffffffffffffffffffffffffffffffffffffc000000000000000000","00000000000000000000000000000000","72bc65aa8e89562e3f274d45af1cd10b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "182","fffffffffffffffffffffffffffffffffffffffffffffe000000000000000000","00000000000000000000000000000000","98551da1a6503276ae1c77625f9ea615", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "183","ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000","00000000000000000000000000000000","0ddfe51ced7e3f4ae927daa3fe452cee", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "184","ffffffffffffffffffffffffffffffffffffffffffffff800000000000000000","00000000000000000000000000000000","db826251e4ce384b80218b0e1da1dd4c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "185","ffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000","00000000000000000000000000000000","2cacf728b88abbad7011ed0e64a1680c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "186","ffffffffffffffffffffffffffffffffffffffffffffffe00000000000000000","00000000000000000000000000000000","330d8ee7c5677e099ac74c9994ee4cfb", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "187","fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000","00000000000000000000000000000000","edf61ae362e882ddc0167474a7a77f3a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "188","fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000","00000000000000000000000000000000","6168b00ba7859e0970ecfd757efecf7c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "189","fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000","00000000000000000000000000000000","d1415447866230d28bb1ea18a4cdfd02", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "190","fffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000","00000000000000000000000000000000","516183392f7a8763afec68a060264141", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "191","ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000","00000000000000000000000000000000","77565c8d73cfd4130b4aa14d8911710f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "192","ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000","00000000000000000000000000000000","37232a4ed21ccc27c19c9610078cabac", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "193","ffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000","00000000000000000000000000000000","804f32ea71828c7d329077e712231666", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "194","ffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000","00000000000000000000000000000000","d64424f23cb97215e9c2c6f28d29eab7", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "195","fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000","00000000000000000000000000000000","023e82b533f68c75c238cebdb2ee89a2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "196","fffffffffffffffffffffffffffffffffffffffffffffffff800000000000000","00000000000000000000000000000000","193a3d24157a51f1ee0893f6777417e7", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "197","fffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000","00000000000000000000000000000000","84ecacfcd400084d078612b1945f2ef5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "198","fffffffffffffffffffffffffffffffffffffffffffffffffe00000000000000","00000000000000000000000000000000","1dcd8bb173259eb33a5242b0de31a455", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "199","ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000","00000000000000000000000000000000","35e9eddbc375e792c19992c19165012b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "200","ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000","00000000000000000000000000000000","8a772231c01dfdd7c98e4cfddcc0807a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "201","ffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000","00000000000000000000000000000000","6eda7ff6b8319180ff0d6e65629d01c3", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "202","ffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000","00000000000000000000000000000000","c267ef0e2d01a993944dd397101413cb", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "203","fffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000","00000000000000000000000000000000","e9f80e9d845bcc0f62926af72eabca39", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "204","fffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000","00000000000000000000000000000000","6702990727aa0878637b45dcd3a3b074", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "205","fffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000","00000000000000000000000000000000","2e2e647d5360e09230a5d738ca33471e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "206","fffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000","00000000000000000000000000000000","1f56413c7add6f43d1d56e4f02190330", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "207","ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000","00000000000000000000000000000000","69cd0606e15af729d6bca143016d9842", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "208","ffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000","00000000000000000000000000000000","a085d7c1a500873a20099c4caa3c3f5b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "209","ffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000","00000000000000000000000000000000","4fc0d230f8891415b87b83f95f2e09d1", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "210","ffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000000","00000000000000000000000000000000","4327d08c523d8eba697a4336507d1f42", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "211","fffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000","00000000000000000000000000000000","7a15aab82701efa5ae36ab1d6b76290f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "212","fffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000","00000000000000000000000000000000","5bf0051893a18bb30e139a58fed0fa54", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "213","fffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000","00000000000000000000000000000000","97e8adf65638fd9cdf3bc22c17fe4dbd", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "214","fffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000","00000000000000000000000000000000","1ee6ee326583a0586491c96418d1a35d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "215","ffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000","00000000000000000000000000000000","26b549c2ec756f82ecc48008e529956b", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "216","ffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000","00000000000000000000000000000000","70377b6da669b072129e057cc28e9ca5", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "217","ffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000","00000000000000000000000000000000","9c94b8b0cb8bcc919072262b3fa05ad9", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "218","ffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000","00000000000000000000000000000000","2fbb83dfd0d7abcb05cd28cad2dfb523", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "219","fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000","00000000000000000000000000000000","96877803de77744bb970d0a91f4debae", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "220","fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000","00000000000000000000000000000000","7379f3370cf6e5ce12ae5969c8eea312", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "221","fffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000","00000000000000000000000000000000","02dc99fa3d4f98ce80985e7233889313", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "222","fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000","00000000000000000000000000000000","1e38e759075ba5cab6457da51844295a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "223","ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000","00000000000000000000000000000000","70bed8dbf615868a1f9d9b05d3e7a267", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "224","ffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000","00000000000000000000000000000000","234b148b8cb1d8c32b287e896903d150", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "225","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000","00000000000000000000000000000000","294b033df4da853f4be3e243f7e513f4", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "226","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000","00000000000000000000000000000000","3f58c950f0367160adec45f2441e7411", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "227","fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000","00000000000000000000000000000000","37f655536a704e5ace182d742a820cf4", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "228","fffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000","00000000000000000000000000000000","ea7bd6bb63418731aeac790fe42d61e8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "229","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000","00000000000000000000000000000000","e74a4c999b4c064e48bb1e413f51e5ea", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "230","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000","00000000000000000000000000000000","ba9ebefdb4ccf30f296cecb3bc1943e8", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "231","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000","00000000000000000000000000000000","3194367a4898c502c13bb7478640a72d", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "232","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000","00000000000000000000000000000000","da797713263d6f33a5478a65ef60d412", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "233","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000","00000000000000000000000000000000","d1ac39bb1ef86b9c1344f214679aa376", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "234","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000","00000000000000000000000000000000","2fdea9e650532be5bc0e7325337fd363", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "235","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000","00000000000000000000000000000000","d3a204dbd9c2af158b6ca67a5156ce4a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "236","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000","00000000000000000000000000000000","3a0a0e75a8da36735aee6684d965a778", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "237","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000","00000000000000000000000000000000","52fc3e620492ea99641ea168da5b6d52", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "238","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000","00000000000000000000000000000000","d2e0c7f15b4772467d2cfc873000b2ca", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "239","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000","00000000000000000000000000000000","563531135e0c4d70a38f8bdb190ba04e", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "240","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000","00000000000000000000000000000000","a8a39a0f5663f4c0fe5f2d3cafff421a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "241","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000","00000000000000000000000000000000","d94b5e90db354c1e42f61fabe167b2c0", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "242","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000","00000000000000000000000000000000","50e6d3c9b6698a7cd276f96b1473f35a", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "243","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000","00000000000000000000000000000000","9338f08e0ebee96905d8f2e825208f43", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "244","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800","00000000000000000000000000000000","8b378c86672aa54a3a266ba19d2580ca", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "245","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00","00000000000000000000000000000000","cca7c3086f5f9511b31233da7cab9160", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "246","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00","00000000000000000000000000000000","5b40ff4ec9be536ba23035fa4f06064c", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "247","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00","00000000000000000000000000000000","60eb5af8416b257149372194e8b88749", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "248","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80","00000000000000000000000000000000","2f005a8aed8a361c92e440c15520cbd1", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "249","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0","00000000000000000000000000000000","7b03627611678a997717578807a800e2", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "250","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0","00000000000000000000000000000000","cf78618f74f6f3696e0a4779b90b5a77", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "251","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0","00000000000000000000000000000000","03720371a04962eaea0a852e69972858", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "252","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8","00000000000000000000000000000000","1f8a8133aa8ccf70e2bd3285831ca6b7", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "253","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc","00000000000000000000000000000000","27936bd27fb1468fc8b48bc483321725", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "254","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe","00000000000000000000000000000000","b07d4f3e2cd2ef2eb545980754dfea0f", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "255","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","00000000000000000000000000000000","4bf85f1b5d54adbc307b0a048389adcb", false);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "0","8000000000000000000000000000000000000000000000000000000000000000","e35a6dcb19b201a01ebcfa8aa22b5759","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "1","c000000000000000000000000000000000000000000000000000000000000000","b29169cdcf2d83e838125a12ee6aa400","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "2","e000000000000000000000000000000000000000000000000000000000000000","d8f3a72fc3cdf74dfaf6c3e6b97b2fa6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "3","f000000000000000000000000000000000000000000000000000000000000000","1c777679d50037c79491a94da76a9a35","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "4","f800000000000000000000000000000000000000000000000000000000000000","9cf4893ecafa0a0247a898e040691559","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "5","fc00000000000000000000000000000000000000000000000000000000000000","8fbb413703735326310a269bd3aa94b2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "6","fe00000000000000000000000000000000000000000000000000000000000000","60e32246bed2b0e859e55c1cc6b26502","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "7","ff00000000000000000000000000000000000000000000000000000000000000","ec52a212f80a09df6317021bc2a9819e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "8","ff80000000000000000000000000000000000000000000000000000000000000","f23e5b600eb70dbccf6c0b1d9a68182c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "9","ffc0000000000000000000000000000000000000000000000000000000000000","a3f599d63a82a968c33fe26590745970","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "10","ffe0000000000000000000000000000000000000000000000000000000000000","d1ccb9b1337002cbac42c520b5d67722","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "11","fff0000000000000000000000000000000000000000000000000000000000000","cc111f6c37cf40a1159d00fb59fb0488","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "12","fff8000000000000000000000000000000000000000000000000000000000000","dc43b51ab609052372989a26e9cdd714","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "13","fffc000000000000000000000000000000000000000000000000000000000000","4dcede8da9e2578f39703d4433dc6459","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "14","fffe000000000000000000000000000000000000000000000000000000000000","1a4c1c263bbccfafc11782894685e3a8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "15","ffff000000000000000000000000000000000000000000000000000000000000","937ad84880db50613423d6d527a2823d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "16","ffff800000000000000000000000000000000000000000000000000000000000","610b71dfc688e150d8152c5b35ebc14d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "17","ffffc00000000000000000000000000000000000000000000000000000000000","27ef2495dabf323885aab39c80f18d8b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "18","ffffe00000000000000000000000000000000000000000000000000000000000","633cafea395bc03adae3a1e2068e4b4e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "19","fffff00000000000000000000000000000000000000000000000000000000000","6e1b482b53761cf631819b749a6f3724","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "20","fffff80000000000000000000000000000000000000000000000000000000000","976e6f851ab52c771998dbb2d71c75a9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "21","fffffc0000000000000000000000000000000000000000000000000000000000","85f2ba84f8c307cf525e124c3e22e6cc","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "22","fffffe0000000000000000000000000000000000000000000000000000000000","6bcca98bf6a835fa64955f72de4115fe","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "23","ffffff0000000000000000000000000000000000000000000000000000000000","2c75e2d36eebd65411f14fd0eb1d2a06","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "24","ffffff8000000000000000000000000000000000000000000000000000000000","bd49295006250ffca5100b6007a0eade","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "25","ffffffc000000000000000000000000000000000000000000000000000000000","a190527d0ef7c70f459cd3940df316ec","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "26","ffffffe000000000000000000000000000000000000000000000000000000000","bbd1097a62433f79449fa97d4ee80dbf","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "27","fffffff000000000000000000000000000000000000000000000000000000000","07058e408f5b99b0e0f061a1761b5b3b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "28","fffffff800000000000000000000000000000000000000000000000000000000","5fd1f13fa0f31e37fabde328f894eac2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "29","fffffffc00000000000000000000000000000000000000000000000000000000","fc4af7c948df26e2ef3e01c1ee5b8f6f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "30","fffffffe00000000000000000000000000000000000000000000000000000000","829fd7208fb92d44a074a677ee9861ac","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "31","ffffffff00000000000000000000000000000000000000000000000000000000","ad9fc613a703251b54c64a0e76431711","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "32","ffffffff80000000000000000000000000000000000000000000000000000000","33ac9eccc4cc75e2711618f80b1548e8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "33","ffffffffc0000000000000000000000000000000000000000000000000000000","2025c74b8ad8f4cda17ee2049c4c902d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "34","ffffffffe0000000000000000000000000000000000000000000000000000000","f85ca05fe528f1ce9b790166e8d551e7","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "35","fffffffff0000000000000000000000000000000000000000000000000000000","6f6238d8966048d4967154e0dad5a6c9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "36","fffffffff8000000000000000000000000000000000000000000000000000000","f2b21b4e7640a9b3346de8b82fb41e49","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "37","fffffffffc000000000000000000000000000000000000000000000000000000","f836f251ad1d11d49dc344628b1884e1","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "38","fffffffffe000000000000000000000000000000000000000000000000000000","077e9470ae7abea5a9769d49182628c3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "39","ffffffffff000000000000000000000000000000000000000000000000000000","e0dcc2d27fc9865633f85223cf0d611f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "40","ffffffffff800000000000000000000000000000000000000000000000000000","be66cfea2fecd6bf0ec7b4352c99bcaa","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "41","ffffffffffc00000000000000000000000000000000000000000000000000000","df31144f87a2ef523facdcf21a427804","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "42","ffffffffffe00000000000000000000000000000000000000000000000000000","b5bb0f5629fb6aae5e1839a3c3625d63","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "43","fffffffffff00000000000000000000000000000000000000000000000000000","3c9db3335306fe1ec612bdbfae6b6028","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "44","fffffffffff80000000000000000000000000000000000000000000000000000","3dd5c34634a79d3cfcc8339760e6f5f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "45","fffffffffffc0000000000000000000000000000000000000000000000000000","82bda118a3ed7af314fa2ccc5c07b761","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "46","fffffffffffe0000000000000000000000000000000000000000000000000000","2937a64f7d4f46fe6fea3b349ec78e38","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "47","ffffffffffff0000000000000000000000000000000000000000000000000000","225f068c28476605735ad671bb8f39f3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "48","ffffffffffff8000000000000000000000000000000000000000000000000000","ae682c5ecd71898e08942ac9aa89875c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "49","ffffffffffffc000000000000000000000000000000000000000000000000000","5e031cb9d676c3022d7f26227e85c38f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "50","ffffffffffffe000000000000000000000000000000000000000000000000000","a78463fb064db5d52bb64bfef64f2dda","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "51","fffffffffffff000000000000000000000000000000000000000000000000000","8aa9b75e784593876c53a00eae5af52b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "52","fffffffffffff800000000000000000000000000000000000000000000000000","3f84566df23da48af692722fe980573a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "53","fffffffffffffc00000000000000000000000000000000000000000000000000","31690b5ed41c7eb42a1e83270a7ff0e6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "54","fffffffffffffe00000000000000000000000000000000000000000000000000","77dd7702646d55f08365e477d3590eda","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "55","ffffffffffffff00000000000000000000000000000000000000000000000000","4c022ac62b3cb78d739cc67b3e20bb7e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "56","ffffffffffffff80000000000000000000000000000000000000000000000000","092fa137ce18b5dfe7906f550bb13370","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "57","ffffffffffffffc0000000000000000000000000000000000000000000000000","3e0cdadf2e68353c0027672c97144dd3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "58","ffffffffffffffe0000000000000000000000000000000000000000000000000","d8c4b200b383fc1f2b2ea677618a1d27","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "59","fffffffffffffff0000000000000000000000000000000000000000000000000","11825f99b0e9bb3477c1c0713b015aac","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "60","fffffffffffffff8000000000000000000000000000000000000000000000000","f8b9fffb5c187f7ddc7ab10f4fb77576","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "61","fffffffffffffffc000000000000000000000000000000000000000000000000","ffb4e87a32b37d6f2c8328d3b5377802","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "62","fffffffffffffffe000000000000000000000000000000000000000000000000","d276c13a5d220f4da9224e74896391ce","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "63","ffffffffffffffff000000000000000000000000000000000000000000000000","94efe7a0e2e031e2536da01df799c927","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "64","ffffffffffffffff800000000000000000000000000000000000000000000000","8f8fd822680a85974e53a5a8eb9d38de","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "65","ffffffffffffffffc00000000000000000000000000000000000000000000000","e0f0a91b2e45f8cc37b7805a3042588d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "66","ffffffffffffffffe00000000000000000000000000000000000000000000000","597a6252255e46d6364dbeeda31e279c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "67","fffffffffffffffff00000000000000000000000000000000000000000000000","f51a0f694442b8f05571797fec7ee8bf","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "68","fffffffffffffffff80000000000000000000000000000000000000000000000","9ff071b165b5198a93dddeebc54d09b5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "69","fffffffffffffffffc0000000000000000000000000000000000000000000000","c20a19fd5758b0c4bc1a5df89cf73877","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "70","fffffffffffffffffe0000000000000000000000000000000000000000000000","97120166307119ca2280e9315668e96f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "71","ffffffffffffffffff0000000000000000000000000000000000000000000000","4b3b9f1e099c2a09dc091e90e4f18f0a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "72","ffffffffffffffffff8000000000000000000000000000000000000000000000","eb040b891d4b37f6851f7ec219cd3f6d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "73","ffffffffffffffffffc000000000000000000000000000000000000000000000","9f0fdec08b7fd79aa39535bea42db92a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "74","ffffffffffffffffffe000000000000000000000000000000000000000000000","2e70f168fc74bf911df240bcd2cef236","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "75","fffffffffffffffffff000000000000000000000000000000000000000000000","462ccd7f5fd1108dbc152f3cacad328b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "76","fffffffffffffffffff800000000000000000000000000000000000000000000","a4af534a7d0b643a01868785d86dfb95","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "77","fffffffffffffffffffc00000000000000000000000000000000000000000000","ab980296197e1a5022326c31da4bf6f3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "78","fffffffffffffffffffe00000000000000000000000000000000000000000000","f97d57b3333b6281b07d486db2d4e20c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "79","ffffffffffffffffffff00000000000000000000000000000000000000000000","f33fa36720231afe4c759ade6bd62eb6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "80","ffffffffffffffffffff80000000000000000000000000000000000000000000","fdcfac0c02ca538343c68117e0a15938","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "81","ffffffffffffffffffffc0000000000000000000000000000000000000000000","ad4916f5ee5772be764fc027b8a6e539","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "82","ffffffffffffffffffffe0000000000000000000000000000000000000000000","2e16873e1678610d7e14c02d002ea845","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "83","fffffffffffffffffffff0000000000000000000000000000000000000000000","4e6e627c1acc51340053a8236d579576","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "84","fffffffffffffffffffff8000000000000000000000000000000000000000000","ab0c8410aeeead92feec1eb430d652cb","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "85","fffffffffffffffffffffc000000000000000000000000000000000000000000","e86f7e23e835e114977f60e1a592202e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "86","fffffffffffffffffffffe000000000000000000000000000000000000000000","e68ad5055a367041fade09d9a70a794b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "87","ffffffffffffffffffffff000000000000000000000000000000000000000000","0791823a3c666bb6162825e78606a7fe","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "88","ffffffffffffffffffffff800000000000000000000000000000000000000000","dcca366a9bf47b7b868b77e25c18a364","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "89","ffffffffffffffffffffffc00000000000000000000000000000000000000000","684c9efc237e4a442965f84bce20247a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "90","ffffffffffffffffffffffe00000000000000000000000000000000000000000","a858411ffbe63fdb9c8aa1bfaed67b52","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "91","fffffffffffffffffffffff00000000000000000000000000000000000000000","04bc3da2179c3015498b0e03910db5b8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "92","fffffffffffffffffffffff80000000000000000000000000000000000000000","40071eeab3f935dbc25d00841460260f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "93","fffffffffffffffffffffffc0000000000000000000000000000000000000000","0ebd7c30ed2016e08ba806ddb008bcc8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "94","fffffffffffffffffffffffe0000000000000000000000000000000000000000","15c6becf0f4cec7129cbd22d1a79b1b8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "95","ffffffffffffffffffffffff0000000000000000000000000000000000000000","0aeede5b91f721700e9e62edbf60b781","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "96","ffffffffffffffffffffffff8000000000000000000000000000000000000000","266581af0dcfbed1585e0a242c64b8df","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "97","ffffffffffffffffffffffffc000000000000000000000000000000000000000","6693dc911662ae473216ba22189a511a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "98","ffffffffffffffffffffffffe000000000000000000000000000000000000000","7606fa36d86473e6fb3a1bb0e2c0adf5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "99","fffffffffffffffffffffffff000000000000000000000000000000000000000","112078e9e11fbb78e26ffb8899e96b9a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "100","fffffffffffffffffffffffff800000000000000000000000000000000000000","40b264e921e9e4a82694589ef3798262","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "101","fffffffffffffffffffffffffc00000000000000000000000000000000000000","8d4595cb4fa7026715f55bd68e2882f9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "102","fffffffffffffffffffffffffe00000000000000000000000000000000000000","b588a302bdbc09197df1edae68926ed9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "103","ffffffffffffffffffffffffff00000000000000000000000000000000000000","33f7502390b8a4a221cfecd0666624ba","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "104","ffffffffffffffffffffffffff80000000000000000000000000000000000000","3d20253adbce3be2373767c4d822c566","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "105","ffffffffffffffffffffffffffc0000000000000000000000000000000000000","a42734a3929bf84cf0116c9856a3c18c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "106","ffffffffffffffffffffffffffe0000000000000000000000000000000000000","e3abc4939457422bb957da3c56938c6d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "107","fffffffffffffffffffffffffff0000000000000000000000000000000000000","972bdd2e7c525130fadc8f76fc6f4b3f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "108","fffffffffffffffffffffffffff8000000000000000000000000000000000000","84a83d7b94c699cbcb8a7d9b61f64093","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "109","fffffffffffffffffffffffffffc000000000000000000000000000000000000","ce61d63514aded03d43e6ebfc3a9001f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "110","fffffffffffffffffffffffffffe000000000000000000000000000000000000","6c839dd58eeae6b8a36af48ed63d2dc9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "111","ffffffffffffffffffffffffffff000000000000000000000000000000000000","cd5ece55b8da3bf622c4100df5de46f9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "112","ffffffffffffffffffffffffffff800000000000000000000000000000000000","3b6f46f40e0ac5fc0a9c1105f800f48d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "113","ffffffffffffffffffffffffffffc00000000000000000000000000000000000","ba26d47da3aeb028de4fb5b3a854a24b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "114","ffffffffffffffffffffffffffffe00000000000000000000000000000000000","87f53bf620d3677268445212904389d5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "115","fffffffffffffffffffffffffffff00000000000000000000000000000000000","10617d28b5e0f4605492b182a5d7f9f6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "116","fffffffffffffffffffffffffffff80000000000000000000000000000000000","9aaec4fabbf6fae2a71feff02e372b39","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "117","fffffffffffffffffffffffffffffc0000000000000000000000000000000000","3a90c62d88b5c42809abf782488ed130","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "118","fffffffffffffffffffffffffffffe0000000000000000000000000000000000","f1f1c5a40899e15772857ccb65c7a09a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "119","ffffffffffffffffffffffffffffff0000000000000000000000000000000000","190843d29b25a3897c692ce1dd81ee52","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "120","ffffffffffffffffffffffffffffff8000000000000000000000000000000000","a866bc65b6941d86e8420a7ffb0964db","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "121","ffffffffffffffffffffffffffffffc000000000000000000000000000000000","8193c6ff85225ced4255e92f6e078a14","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "122","ffffffffffffffffffffffffffffffe000000000000000000000000000000000","9661cb2424d7d4a380d547f9e7ec1cb9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "123","fffffffffffffffffffffffffffffff000000000000000000000000000000000","86f93d9ec08453a071e2e2877877a9c8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "124","fffffffffffffffffffffffffffffff800000000000000000000000000000000","27eefa80ce6a4a9d598e3fec365434d2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "125","fffffffffffffffffffffffffffffffc00000000000000000000000000000000","d62068444578e3ab39ce7ec95dd045dc","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "126","fffffffffffffffffffffffffffffffe00000000000000000000000000000000","b5f71d4dd9a71fe5d8bc8ba7e6ea3048","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "127","ffffffffffffffffffffffffffffffff00000000000000000000000000000000","6825a347ac479d4f9d95c5cb8d3fd7e9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "128","ffffffffffffffffffffffffffffffff80000000000000000000000000000000","e3714e94a5778955cc0346358e94783a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "129","ffffffffffffffffffffffffffffffffc0000000000000000000000000000000","d836b44bb29e0c7d89fa4b2d4b677d2a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "130","ffffffffffffffffffffffffffffffffe0000000000000000000000000000000","5d454b75021d76d4b84f873a8f877b92","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "131","fffffffffffffffffffffffffffffffff0000000000000000000000000000000","c3498f7eced2095314fc28115885b33f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "132","fffffffffffffffffffffffffffffffff8000000000000000000000000000000","6e668856539ad8e405bd123fe6c88530","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "133","fffffffffffffffffffffffffffffffffc000000000000000000000000000000","8680db7f3a87b8605543cfdbe6754076","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "134","fffffffffffffffffffffffffffffffffe000000000000000000000000000000","6c5d03b13069c3658b3179be91b0800c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "135","ffffffffffffffffffffffffffffffffff000000000000000000000000000000","ef1b384ac4d93eda00c92add0995ea5f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "136","ffffffffffffffffffffffffffffffffff800000000000000000000000000000","bf8115805471741bd5ad20a03944790f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "137","ffffffffffffffffffffffffffffffffffc00000000000000000000000000000","c64c24b6894b038b3c0d09b1df068b0b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "138","ffffffffffffffffffffffffffffffffffe00000000000000000000000000000","3967a10cffe27d0178545fbf6a40544b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "139","fffffffffffffffffffffffffffffffffff00000000000000000000000000000","7c85e9c95de1a9ec5a5363a8a053472d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "140","fffffffffffffffffffffffffffffffffff80000000000000000000000000000","a9eec03c8abec7ba68315c2c8c2316e0","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "141","fffffffffffffffffffffffffffffffffffc0000000000000000000000000000","cac8e414c2f388227ae14986fc983524","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "142","fffffffffffffffffffffffffffffffffffe0000000000000000000000000000","5d942b7f4622ce056c3ce3ce5f1dd9d6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "143","ffffffffffffffffffffffffffffffffffff0000000000000000000000000000","d240d648ce21a3020282c3f1b528a0b6","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "144","ffffffffffffffffffffffffffffffffffff8000000000000000000000000000","45d089c36d5c5a4efc689e3b0de10dd5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "145","ffffffffffffffffffffffffffffffffffffc000000000000000000000000000","b4da5df4becb5462e03a0ed00d295629","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "146","ffffffffffffffffffffffffffffffffffffe000000000000000000000000000","dcf4e129136c1a4b7a0f38935cc34b2b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "147","fffffffffffffffffffffffffffffffffffff000000000000000000000000000","d9a4c7618b0ce48a3d5aee1a1c0114c4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "148","fffffffffffffffffffffffffffffffffffff800000000000000000000000000","ca352df025c65c7b0bf306fbee0f36ba","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "149","fffffffffffffffffffffffffffffffffffffc00000000000000000000000000","238aca23fd3409f38af63378ed2f5473","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "150","fffffffffffffffffffffffffffffffffffffe00000000000000000000000000","59836a0e06a79691b36667d5380d8188","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "151","ffffffffffffffffffffffffffffffffffffff00000000000000000000000000","33905080f7acf1cdae0a91fc3e85aee4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "152","ffffffffffffffffffffffffffffffffffffff80000000000000000000000000","72c9e4646dbc3d6320fc6689d93e8833","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "153","ffffffffffffffffffffffffffffffffffffffc0000000000000000000000000","ba77413dea5925b7f5417ea47ff19f59","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "154","ffffffffffffffffffffffffffffffffffffffe0000000000000000000000000","6cae8129f843d86dc786a0fb1a184970","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "155","fffffffffffffffffffffffffffffffffffffff0000000000000000000000000","fcfefb534100796eebbd990206754e19","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "156","fffffffffffffffffffffffffffffffffffffff8000000000000000000000000","8c791d5fdddf470da04f3e6dc4a5b5b5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "157","fffffffffffffffffffffffffffffffffffffffc000000000000000000000000","c93bbdc07a4611ae4bb266ea5034a387","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "158","fffffffffffffffffffffffffffffffffffffffe000000000000000000000000","c102e38e489aa74762f3efc5bb23205a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "159","ffffffffffffffffffffffffffffffffffffffff000000000000000000000000","93201481665cbafc1fcc220bc545fb3d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "160","ffffffffffffffffffffffffffffffffffffffff800000000000000000000000","4960757ec6ce68cf195e454cfd0f32ca","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "161","ffffffffffffffffffffffffffffffffffffffffc00000000000000000000000","feec7ce6a6cbd07c043416737f1bbb33","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "162","ffffffffffffffffffffffffffffffffffffffffe00000000000000000000000","11c5413904487a805d70a8edd9c35527","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "163","fffffffffffffffffffffffffffffffffffffffff00000000000000000000000","347846b2b2e36f1f0324c86f7f1b98e2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "164","fffffffffffffffffffffffffffffffffffffffff80000000000000000000000","332eee1a0cbd19ca2d69b426894044f0","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "165","fffffffffffffffffffffffffffffffffffffffffc0000000000000000000000","866b5b3977ba6efa5128efbda9ff03cd","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "166","fffffffffffffffffffffffffffffffffffffffffe0000000000000000000000","cc1445ee94c0f08cdee5c344ecd1e233","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "167","ffffffffffffffffffffffffffffffffffffffffff0000000000000000000000","be288319029363c2622feba4b05dfdfe","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "168","ffffffffffffffffffffffffffffffffffffffffff8000000000000000000000","cfd1875523f3cd21c395651e6ee15e56","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "169","ffffffffffffffffffffffffffffffffffffffffffc000000000000000000000","cb5a408657837c53bf16f9d8465dce19","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "170","ffffffffffffffffffffffffffffffffffffffffffe000000000000000000000","ca0bf42cb107f55ccff2fc09ee08ca15","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "171","fffffffffffffffffffffffffffffffffffffffffff000000000000000000000","fdd9bbb4a7dc2e4a23536a5880a2db67","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "172","fffffffffffffffffffffffffffffffffffffffffff800000000000000000000","ede447b362c484993dec9442a3b46aef","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "173","fffffffffffffffffffffffffffffffffffffffffffc00000000000000000000","10dffb05904bff7c4781df780ad26837","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "174","fffffffffffffffffffffffffffffffffffffffffffe00000000000000000000","c33bc13e8de88ac25232aa7496398783","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "175","ffffffffffffffffffffffffffffffffffffffffffff00000000000000000000","ca359c70803a3b2a3d542e8781dea975","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "176","ffffffffffffffffffffffffffffffffffffffffffff80000000000000000000","bcc65b526f88d05b89ce8a52021fdb06","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "177","ffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000","db91a38855c8c4643851fbfb358b0109","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "178","ffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000","ca6e8893a114ae8e27d5ab03a5499610","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "179","fffffffffffffffffffffffffffffffffffffffffffff0000000000000000000","6629d2b8df97da728cdd8b1e7f945077","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "180","fffffffffffffffffffffffffffffffffffffffffffff8000000000000000000","4570a5a18cfc0dd582f1d88d5c9a1720","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "181","fffffffffffffffffffffffffffffffffffffffffffffc000000000000000000","72bc65aa8e89562e3f274d45af1cd10b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "182","fffffffffffffffffffffffffffffffffffffffffffffe000000000000000000","98551da1a6503276ae1c77625f9ea615","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "183","ffffffffffffffffffffffffffffffffffffffffffffff000000000000000000","0ddfe51ced7e3f4ae927daa3fe452cee","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "184","ffffffffffffffffffffffffffffffffffffffffffffff800000000000000000","db826251e4ce384b80218b0e1da1dd4c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "185","ffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000","2cacf728b88abbad7011ed0e64a1680c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "186","ffffffffffffffffffffffffffffffffffffffffffffffe00000000000000000","330d8ee7c5677e099ac74c9994ee4cfb","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "187","fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000","edf61ae362e882ddc0167474a7a77f3a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "188","fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000","6168b00ba7859e0970ecfd757efecf7c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "189","fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000","d1415447866230d28bb1ea18a4cdfd02","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "190","fffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000","516183392f7a8763afec68a060264141","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "191","ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000","77565c8d73cfd4130b4aa14d8911710f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "192","ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000","37232a4ed21ccc27c19c9610078cabac","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "193","ffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000","804f32ea71828c7d329077e712231666","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "194","ffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000","d64424f23cb97215e9c2c6f28d29eab7","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "195","fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000","023e82b533f68c75c238cebdb2ee89a2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "196","fffffffffffffffffffffffffffffffffffffffffffffffff800000000000000","193a3d24157a51f1ee0893f6777417e7","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "197","fffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000","84ecacfcd400084d078612b1945f2ef5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "198","fffffffffffffffffffffffffffffffffffffffffffffffffe00000000000000","1dcd8bb173259eb33a5242b0de31a455","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "199","ffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000","35e9eddbc375e792c19992c19165012b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "200","ffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000","8a772231c01dfdd7c98e4cfddcc0807a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "201","ffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000","6eda7ff6b8319180ff0d6e65629d01c3","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "202","ffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000","c267ef0e2d01a993944dd397101413cb","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "203","fffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000","e9f80e9d845bcc0f62926af72eabca39","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "204","fffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000","6702990727aa0878637b45dcd3a3b074","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "205","fffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000","2e2e647d5360e09230a5d738ca33471e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "206","fffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000","1f56413c7add6f43d1d56e4f02190330","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "207","ffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000","69cd0606e15af729d6bca143016d9842","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "208","ffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000","a085d7c1a500873a20099c4caa3c3f5b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "209","ffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000","4fc0d230f8891415b87b83f95f2e09d1","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "210","ffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000000","4327d08c523d8eba697a4336507d1f42","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "211","fffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000","7a15aab82701efa5ae36ab1d6b76290f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "212","fffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000","5bf0051893a18bb30e139a58fed0fa54","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "213","fffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000","97e8adf65638fd9cdf3bc22c17fe4dbd","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "214","fffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000","1ee6ee326583a0586491c96418d1a35d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "215","ffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000","26b549c2ec756f82ecc48008e529956b","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "216","ffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000","70377b6da669b072129e057cc28e9ca5","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "217","ffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000","9c94b8b0cb8bcc919072262b3fa05ad9","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "218","ffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000","2fbb83dfd0d7abcb05cd28cad2dfb523","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "219","fffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000","96877803de77744bb970d0a91f4debae","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "220","fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000","7379f3370cf6e5ce12ae5969c8eea312","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "221","fffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000","02dc99fa3d4f98ce80985e7233889313","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "222","fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000","1e38e759075ba5cab6457da51844295a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "223","ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000","70bed8dbf615868a1f9d9b05d3e7a267","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "224","ffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000","234b148b8cb1d8c32b287e896903d150","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "225","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000","294b033df4da853f4be3e243f7e513f4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "226","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000","3f58c950f0367160adec45f2441e7411","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "227","fffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000","37f655536a704e5ace182d742a820cf4","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "228","fffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000","ea7bd6bb63418731aeac790fe42d61e8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "229","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000","e74a4c999b4c064e48bb1e413f51e5ea","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "230","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000","ba9ebefdb4ccf30f296cecb3bc1943e8","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "231","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000","3194367a4898c502c13bb7478640a72d","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "232","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000","da797713263d6f33a5478a65ef60d412","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "233","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000","d1ac39bb1ef86b9c1344f214679aa376","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "234","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000","2fdea9e650532be5bc0e7325337fd363","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "235","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000","d3a204dbd9c2af158b6ca67a5156ce4a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "236","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000","3a0a0e75a8da36735aee6684d965a778","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "237","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000","52fc3e620492ea99641ea168da5b6d52","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "238","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000","d2e0c7f15b4772467d2cfc873000b2ca","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "239","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000","563531135e0c4d70a38f8bdb190ba04e","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "240","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000","a8a39a0f5663f4c0fe5f2d3cafff421a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "241","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000","d94b5e90db354c1e42f61fabe167b2c0","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "242","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000","50e6d3c9b6698a7cd276f96b1473f35a","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "243","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000","9338f08e0ebee96905d8f2e825208f43","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "244","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800","8b378c86672aa54a3a266ba19d2580ca","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "245","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00","cca7c3086f5f9511b31233da7cab9160","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "246","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00","5b40ff4ec9be536ba23035fa4f06064c","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "247","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00","60eb5af8416b257149372194e8b88749","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "248","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80","2f005a8aed8a361c92e440c15520cbd1","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "249","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0","7b03627611678a997717578807a800e2","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "250","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0","cf78618f74f6f3696e0a4779b90b5a77","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "251","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0","03720371a04962eaea0a852e69972858","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "252","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8","1f8a8133aa8ccf70e2bd3285831ca6b7","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "253","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc","27936bd27fb1468fc8b48bc483321725","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "254","fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe","b07d4f3e2cd2ef2eb545980754dfea0f","00000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarKey256.rsp", "255","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","4bf85f1b5d54adbc307b0a048389adcb","00000000000000000000000000000000", true);
}

static void
aes_test_vartxt_256(void)
{
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "0","0000000000000000000000000000000000000000000000000000000000000000","80000000000000000000000000000000","ddc6bf790c15760d8d9aeb6f9a75fd4e", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "1","0000000000000000000000000000000000000000000000000000000000000000","c0000000000000000000000000000000","0a6bdc6d4c1e6280301fd8e97ddbe601", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "2","0000000000000000000000000000000000000000000000000000000000000000","e0000000000000000000000000000000","9b80eefb7ebe2d2b16247aa0efc72f5d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "3","0000000000000000000000000000000000000000000000000000000000000000","f0000000000000000000000000000000","7f2c5ece07a98d8bee13c51177395ff7", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "4","0000000000000000000000000000000000000000000000000000000000000000","f8000000000000000000000000000000","7818d800dcf6f4be1e0e94f403d1e4c2", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "5","0000000000000000000000000000000000000000000000000000000000000000","fc000000000000000000000000000000","e74cd1c92f0919c35a0324123d6177d3", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "6","0000000000000000000000000000000000000000000000000000000000000000","fe000000000000000000000000000000","8092a4dcf2da7e77e93bdd371dfed82e", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "7","0000000000000000000000000000000000000000000000000000000000000000","ff000000000000000000000000000000","49af6b372135acef10132e548f217b17", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "8","0000000000000000000000000000000000000000000000000000000000000000","ff800000000000000000000000000000","8bcd40f94ebb63b9f7909676e667f1e7", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "9","0000000000000000000000000000000000000000000000000000000000000000","ffc00000000000000000000000000000","fe1cffb83f45dcfb38b29be438dbd3ab", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "10","0000000000000000000000000000000000000000000000000000000000000000","ffe00000000000000000000000000000","0dc58a8d886623705aec15cb1e70dc0e", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "11","0000000000000000000000000000000000000000000000000000000000000000","fff00000000000000000000000000000","c218faa16056bd0774c3e8d79c35a5e4", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "12","0000000000000000000000000000000000000000000000000000000000000000","fff80000000000000000000000000000","047bba83f7aa841731504e012208fc9e", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "13","0000000000000000000000000000000000000000000000000000000000000000","fffc0000000000000000000000000000","dc8f0e4915fd81ba70a331310882f6da", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "14","0000000000000000000000000000000000000000000000000000000000000000","fffe0000000000000000000000000000","1569859ea6b7206c30bf4fd0cbfac33c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "15","0000000000000000000000000000000000000000000000000000000000000000","ffff0000000000000000000000000000","300ade92f88f48fa2df730ec16ef44cd", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "16","0000000000000000000000000000000000000000000000000000000000000000","ffff8000000000000000000000000000","1fe6cc3c05965dc08eb0590c95ac71d0", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "17","0000000000000000000000000000000000000000000000000000000000000000","ffffc000000000000000000000000000","59e858eaaa97fec38111275b6cf5abc0", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "18","0000000000000000000000000000000000000000000000000000000000000000","ffffe000000000000000000000000000","2239455e7afe3b0616100288cc5a723b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "19","0000000000000000000000000000000000000000000000000000000000000000","fffff000000000000000000000000000","3ee500c5c8d63479717163e55c5c4522", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "20","0000000000000000000000000000000000000000000000000000000000000000","fffff800000000000000000000000000","d5e38bf15f16d90e3e214041d774daa8", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "21","0000000000000000000000000000000000000000000000000000000000000000","fffffc00000000000000000000000000","b1f4066e6f4f187dfe5f2ad1b17819d0", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "22","0000000000000000000000000000000000000000000000000000000000000000","fffffe00000000000000000000000000","6ef4cc4de49b11065d7af2909854794a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "23","0000000000000000000000000000000000000000000000000000000000000000","ffffff00000000000000000000000000","ac86bc606b6640c309e782f232bf367f", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "24","0000000000000000000000000000000000000000000000000000000000000000","ffffff80000000000000000000000000","36aff0ef7bf3280772cf4cac80a0d2b2", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "25","0000000000000000000000000000000000000000000000000000000000000000","ffffffc0000000000000000000000000","1f8eedea0f62a1406d58cfc3ecea72cf", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "26","0000000000000000000000000000000000000000000000000000000000000000","ffffffe0000000000000000000000000","abf4154a3375a1d3e6b1d454438f95a6", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "27","0000000000000000000000000000000000000000000000000000000000000000","fffffff0000000000000000000000000","96f96e9d607f6615fc192061ee648b07", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "28","0000000000000000000000000000000000000000000000000000000000000000","fffffff8000000000000000000000000","cf37cdaaa0d2d536c71857634c792064", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "29","0000000000000000000000000000000000000000000000000000000000000000","fffffffc000000000000000000000000","fbd6640c80245c2b805373f130703127", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "30","0000000000000000000000000000000000000000000000000000000000000000","fffffffe000000000000000000000000","8d6a8afe55a6e481badae0d146f436db", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "31","0000000000000000000000000000000000000000000000000000000000000000","ffffffff000000000000000000000000","6a4981f2915e3e68af6c22385dd06756", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "32","0000000000000000000000000000000000000000000000000000000000000000","ffffffff800000000000000000000000","42a1136e5f8d8d21d3101998642d573b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "33","0000000000000000000000000000000000000000000000000000000000000000","ffffffffc00000000000000000000000","9b471596dc69ae1586cee6158b0b0181", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "34","0000000000000000000000000000000000000000000000000000000000000000","ffffffffe00000000000000000000000","753665c4af1eff33aa8b628bf8741cfd", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "35","0000000000000000000000000000000000000000000000000000000000000000","fffffffff00000000000000000000000","9a682acf40be01f5b2a4193c9a82404d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "36","0000000000000000000000000000000000000000000000000000000000000000","fffffffff80000000000000000000000","54fafe26e4287f17d1935f87eb9ade01", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "37","0000000000000000000000000000000000000000000000000000000000000000","fffffffffc0000000000000000000000","49d541b2e74cfe73e6a8e8225f7bd449", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "38","0000000000000000000000000000000000000000000000000000000000000000","fffffffffe0000000000000000000000","11a45530f624ff6f76a1b3826626ff7b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "39","0000000000000000000000000000000000000000000000000000000000000000","ffffffffff0000000000000000000000","f96b0c4a8bc6c86130289f60b43b8fba", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "40","0000000000000000000000000000000000000000000000000000000000000000","ffffffffff8000000000000000000000","48c7d0e80834ebdc35b6735f76b46c8b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "41","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffc000000000000000000000","2463531ab54d66955e73edc4cb8eaa45", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "42","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffe000000000000000000000","ac9bd8e2530469134b9d5b065d4f565b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "43","0000000000000000000000000000000000000000000000000000000000000000","fffffffffff000000000000000000000","3f5f9106d0e52f973d4890e6f37e8a00", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "44","0000000000000000000000000000000000000000000000000000000000000000","fffffffffff800000000000000000000","20ebc86f1304d272e2e207e59db639f0", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "45","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffc00000000000000000000","e67ae6426bf9526c972cff072b52252c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "46","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffe00000000000000000000","1a518dddaf9efa0d002cc58d107edfc8", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "47","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffff00000000000000000000","ead731af4d3a2fe3b34bed047942a49f", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "48","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffff80000000000000000000","b1d4efe40242f83e93b6c8d7efb5eae9", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "49","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffc0000000000000000000","cd2b1fec11fd906c5c7630099443610a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "50","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffe0000000000000000000","a1853fe47fe29289d153161d06387d21", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "51","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffff0000000000000000000","4632154179a555c17ea604d0889fab14", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "52","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffff8000000000000000000","dd27cac6401a022e8f38f9f93e774417", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "53","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffc000000000000000000","c090313eb98674f35f3123385fb95d4d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "54","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffe000000000000000000","cc3526262b92f02edce548f716b9f45c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "55","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffff000000000000000000","c0838d1a2b16a7c7f0dfcc433c399c33", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "56","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffff800000000000000000","0d9ac756eb297695eed4d382eb126d26", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "57","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffc00000000000000000","56ede9dda3f6f141bff1757fa689c3e1", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "58","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffe00000000000000000","768f520efe0f23e61d3ec8ad9ce91774", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "59","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffff00000000000000000","b1144ddfa75755213390e7c596660490", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "60","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffff80000000000000000","1d7c0c4040b355b9d107a99325e3b050", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "61","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffc0000000000000000","d8e2bb1ae8ee3dcf5bf7d6c38da82a1a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "62","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffe0000000000000000","faf82d178af25a9886a47e7f789b98d7", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "63","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffff0000000000000000","9b58dbfd77fe5aca9cfc190cd1b82d19", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "64","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffff8000000000000000","77f392089042e478ac16c0c86a0b5db5", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "65","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffc000000000000000","19f08e3420ee69b477ca1420281c4782", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "66","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffe000000000000000","a1b19beee4e117139f74b3c53fdcb875", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "67","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffff000000000000000","a37a5869b218a9f3a0868d19aea0ad6a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "68","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffff800000000000000","bc3594e865bcd0261b13202731f33580", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "69","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffc00000000000000","811441ce1d309eee7185e8c752c07557", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "70","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffe00000000000000","959971ce4134190563518e700b9874d1", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "71","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffff00000000000000","76b5614a042707c98e2132e2e805fe63", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "72","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffff80000000000000","7d9fa6a57530d0f036fec31c230b0cc6", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "73","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffc0000000000000","964153a83bf6989a4ba80daa91c3e081", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "74","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffe0000000000000","a013014d4ce8054cf2591d06f6f2f176", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "75","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffff0000000000000","d1c5f6399bf382502e385eee1474a869", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "76","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffff8000000000000","0007e20b8298ec354f0f5fe7470f36bd", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "77","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffc000000000000","b95ba05b332da61ef63a2b31fcad9879", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "78","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffe000000000000","4620a49bd967491561669ab25dce45f4", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "79","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffff000000000000","12e71214ae8e04f0bb63d7425c6f14d5", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "80","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffff800000000000","4cc42fc1407b008fe350907c092e80ac", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "81","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffc00000000000","08b244ce7cbc8ee97fbba808cb146fda", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "82","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffe00000000000","39b333e8694f21546ad1edd9d87ed95b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "83","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffff00000000000","3b271f8ab2e6e4a20ba8090f43ba78f3", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "84","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffff80000000000","9ad983f3bf651cd0393f0a73cccdea50", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "85","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffc0000000000","8f476cbff75c1f725ce18e4bbcd19b32", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "86","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffe0000000000","905b6267f1d6ab5320835a133f096f2a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "87","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffff0000000000","145b60d6d0193c23f4221848a892d61a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "88","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffff8000000000","55cfb3fb6d75cad0445bbc8dafa25b0f", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "89","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffc000000000","7b8e7098e357ef71237d46d8b075b0f5", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "90","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffe000000000","2bf27229901eb40f2df9d8398d1505ae", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "91","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffff000000000","83a63402a77f9ad5c1e931a931ecd706", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "92","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffff800000000","6f8ba6521152d31f2bada1843e26b973", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "93","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffc00000000","e5c3b8e30fd2d8e6239b17b44bd23bbd", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "94","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffe00000000","1ac1f7102c59933e8b2ddc3f14e94baa", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "95","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffff00000000","21d9ba49f276b45f11af8fc71a088e3d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "96","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffff80000000","649f1cddc3792b4638635a392bc9bade", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "97","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffc0000000","e2775e4b59c1bc2e31a2078c11b5a08c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "98","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffe0000000","2be1fae5048a25582a679ca10905eb80", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "99","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffff0000000","da86f292c6f41ea34fb2068df75ecc29", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "100","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffff8000000","220df19f85d69b1b562fa69a3c5beca5", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "101","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffc000000","1f11d5d0355e0b556ccdb6c7f5083b4d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "102","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffe000000","62526b78be79cb384633c91f83b4151b", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "103","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffff000000","90ddbcb950843592dd47bbef00fdc876", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "104","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffff800000","2fd0e41c5b8402277354a7391d2618e2", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "105","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffc00000","3cdf13e72dee4c581bafec70b85f9660", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "106","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffe00000","afa2ffc137577092e2b654fa199d2c43", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "107","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffff00000","8d683ee63e60d208e343ce48dbc44cac", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "108","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffff80000","705a4ef8ba2133729c20185c3d3a4763", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "109","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffc0000","0861a861c3db4e94194211b77ed761b9", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "110","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffe0000","4b00c27e8b26da7eab9d3a88dec8b031", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "111","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffff0000","5f397bf03084820cc8810d52e5b666e9", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "112","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffff8000","63fafabb72c07bfbd3ddc9b1203104b8", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "113","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffc000","683e2140585b18452dd4ffbb93c95df9", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "114","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffe000","286894e48e537f8763b56707d7d155c8", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "115","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffff000","a423deabc173dcf7e2c4c53e77d37cd1", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "116","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffff800","eb8168313e1cfdfdb5e986d5429cf172", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "117","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffc00","27127daafc9accd2fb334ec3eba52323", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "118","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffe00","ee0715b96f72e3f7a22a5064fc592f4c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "119","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffff00","29ee526770f2a11dcfa989d1ce88830f", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "120","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffff80","0493370e054b09871130fe49af730a5a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "121","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffc0","9b7b940f6c509f9e44a4ee140448ee46", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "122","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffe0","2915be4a1ecfdcbe3e023811a12bb6c7", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "123","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffff0","7240e524bc51d8c4d440b1be55d1062c", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "124","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffff8","da63039d38cb4612b2dc36ba26684b93", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "125","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffffc","0f59cb5a4b522e2ac56c1a64f558ad9a", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "126","0000000000000000000000000000000000000000000000000000000000000000","fffffffffffffffffffffffffffffffe","7bfe9d876c6d63c1d035da8fe21c409d", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "127","0000000000000000000000000000000000000000000000000000000000000000","ffffffffffffffffffffffffffffffff","acdace8078a32b1a182bfa4987ca1347", false);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "0","0000000000000000000000000000000000000000000000000000000000000000","ddc6bf790c15760d8d9aeb6f9a75fd4e","80000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "1","0000000000000000000000000000000000000000000000000000000000000000","0a6bdc6d4c1e6280301fd8e97ddbe601","c0000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "2","0000000000000000000000000000000000000000000000000000000000000000","9b80eefb7ebe2d2b16247aa0efc72f5d","e0000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "3","0000000000000000000000000000000000000000000000000000000000000000","7f2c5ece07a98d8bee13c51177395ff7","f0000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "4","0000000000000000000000000000000000000000000000000000000000000000","7818d800dcf6f4be1e0e94f403d1e4c2","f8000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "5","0000000000000000000000000000000000000000000000000000000000000000","e74cd1c92f0919c35a0324123d6177d3","fc000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "6","0000000000000000000000000000000000000000000000000000000000000000","8092a4dcf2da7e77e93bdd371dfed82e","fe000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "7","0000000000000000000000000000000000000000000000000000000000000000","49af6b372135acef10132e548f217b17","ff000000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "8","0000000000000000000000000000000000000000000000000000000000000000","8bcd40f94ebb63b9f7909676e667f1e7","ff800000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "9","0000000000000000000000000000000000000000000000000000000000000000","fe1cffb83f45dcfb38b29be438dbd3ab","ffc00000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "10","0000000000000000000000000000000000000000000000000000000000000000","0dc58a8d886623705aec15cb1e70dc0e","ffe00000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "11","0000000000000000000000000000000000000000000000000000000000000000","c218faa16056bd0774c3e8d79c35a5e4","fff00000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "12","0000000000000000000000000000000000000000000000000000000000000000","047bba83f7aa841731504e012208fc9e","fff80000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "13","0000000000000000000000000000000000000000000000000000000000000000","dc8f0e4915fd81ba70a331310882f6da","fffc0000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "14","0000000000000000000000000000000000000000000000000000000000000000","1569859ea6b7206c30bf4fd0cbfac33c","fffe0000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "15","0000000000000000000000000000000000000000000000000000000000000000","300ade92f88f48fa2df730ec16ef44cd","ffff0000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "16","0000000000000000000000000000000000000000000000000000000000000000","1fe6cc3c05965dc08eb0590c95ac71d0","ffff8000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "17","0000000000000000000000000000000000000000000000000000000000000000","59e858eaaa97fec38111275b6cf5abc0","ffffc000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "18","0000000000000000000000000000000000000000000000000000000000000000","2239455e7afe3b0616100288cc5a723b","ffffe000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "19","0000000000000000000000000000000000000000000000000000000000000000","3ee500c5c8d63479717163e55c5c4522","fffff000000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "20","0000000000000000000000000000000000000000000000000000000000000000","d5e38bf15f16d90e3e214041d774daa8","fffff800000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "21","0000000000000000000000000000000000000000000000000000000000000000","b1f4066e6f4f187dfe5f2ad1b17819d0","fffffc00000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "22","0000000000000000000000000000000000000000000000000000000000000000","6ef4cc4de49b11065d7af2909854794a","fffffe00000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "23","0000000000000000000000000000000000000000000000000000000000000000","ac86bc606b6640c309e782f232bf367f","ffffff00000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "24","0000000000000000000000000000000000000000000000000000000000000000","36aff0ef7bf3280772cf4cac80a0d2b2","ffffff80000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "25","0000000000000000000000000000000000000000000000000000000000000000","1f8eedea0f62a1406d58cfc3ecea72cf","ffffffc0000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "26","0000000000000000000000000000000000000000000000000000000000000000","abf4154a3375a1d3e6b1d454438f95a6","ffffffe0000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "27","0000000000000000000000000000000000000000000000000000000000000000","96f96e9d607f6615fc192061ee648b07","fffffff0000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "28","0000000000000000000000000000000000000000000000000000000000000000","cf37cdaaa0d2d536c71857634c792064","fffffff8000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "29","0000000000000000000000000000000000000000000000000000000000000000","fbd6640c80245c2b805373f130703127","fffffffc000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "30","0000000000000000000000000000000000000000000000000000000000000000","8d6a8afe55a6e481badae0d146f436db","fffffffe000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "31","0000000000000000000000000000000000000000000000000000000000000000","6a4981f2915e3e68af6c22385dd06756","ffffffff000000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "32","0000000000000000000000000000000000000000000000000000000000000000","42a1136e5f8d8d21d3101998642d573b","ffffffff800000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "33","0000000000000000000000000000000000000000000000000000000000000000","9b471596dc69ae1586cee6158b0b0181","ffffffffc00000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "34","0000000000000000000000000000000000000000000000000000000000000000","753665c4af1eff33aa8b628bf8741cfd","ffffffffe00000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "35","0000000000000000000000000000000000000000000000000000000000000000","9a682acf40be01f5b2a4193c9a82404d","fffffffff00000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "36","0000000000000000000000000000000000000000000000000000000000000000","54fafe26e4287f17d1935f87eb9ade01","fffffffff80000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "37","0000000000000000000000000000000000000000000000000000000000000000","49d541b2e74cfe73e6a8e8225f7bd449","fffffffffc0000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "38","0000000000000000000000000000000000000000000000000000000000000000","11a45530f624ff6f76a1b3826626ff7b","fffffffffe0000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "39","0000000000000000000000000000000000000000000000000000000000000000","f96b0c4a8bc6c86130289f60b43b8fba","ffffffffff0000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "40","0000000000000000000000000000000000000000000000000000000000000000","48c7d0e80834ebdc35b6735f76b46c8b","ffffffffff8000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "41","0000000000000000000000000000000000000000000000000000000000000000","2463531ab54d66955e73edc4cb8eaa45","ffffffffffc000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "42","0000000000000000000000000000000000000000000000000000000000000000","ac9bd8e2530469134b9d5b065d4f565b","ffffffffffe000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "43","0000000000000000000000000000000000000000000000000000000000000000","3f5f9106d0e52f973d4890e6f37e8a00","fffffffffff000000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "44","0000000000000000000000000000000000000000000000000000000000000000","20ebc86f1304d272e2e207e59db639f0","fffffffffff800000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "45","0000000000000000000000000000000000000000000000000000000000000000","e67ae6426bf9526c972cff072b52252c","fffffffffffc00000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "46","0000000000000000000000000000000000000000000000000000000000000000","1a518dddaf9efa0d002cc58d107edfc8","fffffffffffe00000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "47","0000000000000000000000000000000000000000000000000000000000000000","ead731af4d3a2fe3b34bed047942a49f","ffffffffffff00000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "48","0000000000000000000000000000000000000000000000000000000000000000","b1d4efe40242f83e93b6c8d7efb5eae9","ffffffffffff80000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "49","0000000000000000000000000000000000000000000000000000000000000000","cd2b1fec11fd906c5c7630099443610a","ffffffffffffc0000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "50","0000000000000000000000000000000000000000000000000000000000000000","a1853fe47fe29289d153161d06387d21","ffffffffffffe0000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "51","0000000000000000000000000000000000000000000000000000000000000000","4632154179a555c17ea604d0889fab14","fffffffffffff0000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "52","0000000000000000000000000000000000000000000000000000000000000000","dd27cac6401a022e8f38f9f93e774417","fffffffffffff8000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "53","0000000000000000000000000000000000000000000000000000000000000000","c090313eb98674f35f3123385fb95d4d","fffffffffffffc000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "54","0000000000000000000000000000000000000000000000000000000000000000","cc3526262b92f02edce548f716b9f45c","fffffffffffffe000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "55","0000000000000000000000000000000000000000000000000000000000000000","c0838d1a2b16a7c7f0dfcc433c399c33","ffffffffffffff000000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "56","0000000000000000000000000000000000000000000000000000000000000000","0d9ac756eb297695eed4d382eb126d26","ffffffffffffff800000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "57","0000000000000000000000000000000000000000000000000000000000000000","56ede9dda3f6f141bff1757fa689c3e1","ffffffffffffffc00000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "58","0000000000000000000000000000000000000000000000000000000000000000","768f520efe0f23e61d3ec8ad9ce91774","ffffffffffffffe00000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "59","0000000000000000000000000000000000000000000000000000000000000000","b1144ddfa75755213390e7c596660490","fffffffffffffff00000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "60","0000000000000000000000000000000000000000000000000000000000000000","1d7c0c4040b355b9d107a99325e3b050","fffffffffffffff80000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "61","0000000000000000000000000000000000000000000000000000000000000000","d8e2bb1ae8ee3dcf5bf7d6c38da82a1a","fffffffffffffffc0000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "62","0000000000000000000000000000000000000000000000000000000000000000","faf82d178af25a9886a47e7f789b98d7","fffffffffffffffe0000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "63","0000000000000000000000000000000000000000000000000000000000000000","9b58dbfd77fe5aca9cfc190cd1b82d19","ffffffffffffffff0000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "64","0000000000000000000000000000000000000000000000000000000000000000","77f392089042e478ac16c0c86a0b5db5","ffffffffffffffff8000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "65","0000000000000000000000000000000000000000000000000000000000000000","19f08e3420ee69b477ca1420281c4782","ffffffffffffffffc000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "66","0000000000000000000000000000000000000000000000000000000000000000","a1b19beee4e117139f74b3c53fdcb875","ffffffffffffffffe000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "67","0000000000000000000000000000000000000000000000000000000000000000","a37a5869b218a9f3a0868d19aea0ad6a","fffffffffffffffff000000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "68","0000000000000000000000000000000000000000000000000000000000000000","bc3594e865bcd0261b13202731f33580","fffffffffffffffff800000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "69","0000000000000000000000000000000000000000000000000000000000000000","811441ce1d309eee7185e8c752c07557","fffffffffffffffffc00000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "70","0000000000000000000000000000000000000000000000000000000000000000","959971ce4134190563518e700b9874d1","fffffffffffffffffe00000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "71","0000000000000000000000000000000000000000000000000000000000000000","76b5614a042707c98e2132e2e805fe63","ffffffffffffffffff00000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "72","0000000000000000000000000000000000000000000000000000000000000000","7d9fa6a57530d0f036fec31c230b0cc6","ffffffffffffffffff80000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "73","0000000000000000000000000000000000000000000000000000000000000000","964153a83bf6989a4ba80daa91c3e081","ffffffffffffffffffc0000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "74","0000000000000000000000000000000000000000000000000000000000000000","a013014d4ce8054cf2591d06f6f2f176","ffffffffffffffffffe0000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "75","0000000000000000000000000000000000000000000000000000000000000000","d1c5f6399bf382502e385eee1474a869","fffffffffffffffffff0000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "76","0000000000000000000000000000000000000000000000000000000000000000","0007e20b8298ec354f0f5fe7470f36bd","fffffffffffffffffff8000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "77","0000000000000000000000000000000000000000000000000000000000000000","b95ba05b332da61ef63a2b31fcad9879","fffffffffffffffffffc000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "78","0000000000000000000000000000000000000000000000000000000000000000","4620a49bd967491561669ab25dce45f4","fffffffffffffffffffe000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "79","0000000000000000000000000000000000000000000000000000000000000000","12e71214ae8e04f0bb63d7425c6f14d5","ffffffffffffffffffff000000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "80","0000000000000000000000000000000000000000000000000000000000000000","4cc42fc1407b008fe350907c092e80ac","ffffffffffffffffffff800000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "81","0000000000000000000000000000000000000000000000000000000000000000","08b244ce7cbc8ee97fbba808cb146fda","ffffffffffffffffffffc00000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "82","0000000000000000000000000000000000000000000000000000000000000000","39b333e8694f21546ad1edd9d87ed95b","ffffffffffffffffffffe00000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "83","0000000000000000000000000000000000000000000000000000000000000000","3b271f8ab2e6e4a20ba8090f43ba78f3","fffffffffffffffffffff00000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "84","0000000000000000000000000000000000000000000000000000000000000000","9ad983f3bf651cd0393f0a73cccdea50","fffffffffffffffffffff80000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "85","0000000000000000000000000000000000000000000000000000000000000000","8f476cbff75c1f725ce18e4bbcd19b32","fffffffffffffffffffffc0000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "86","0000000000000000000000000000000000000000000000000000000000000000","905b6267f1d6ab5320835a133f096f2a","fffffffffffffffffffffe0000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "87","0000000000000000000000000000000000000000000000000000000000000000","145b60d6d0193c23f4221848a892d61a","ffffffffffffffffffffff0000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "88","0000000000000000000000000000000000000000000000000000000000000000","55cfb3fb6d75cad0445bbc8dafa25b0f","ffffffffffffffffffffff8000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "89","0000000000000000000000000000000000000000000000000000000000000000","7b8e7098e357ef71237d46d8b075b0f5","ffffffffffffffffffffffc000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "90","0000000000000000000000000000000000000000000000000000000000000000","2bf27229901eb40f2df9d8398d1505ae","ffffffffffffffffffffffe000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "91","0000000000000000000000000000000000000000000000000000000000000000","83a63402a77f9ad5c1e931a931ecd706","fffffffffffffffffffffff000000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "92","0000000000000000000000000000000000000000000000000000000000000000","6f8ba6521152d31f2bada1843e26b973","fffffffffffffffffffffff800000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "93","0000000000000000000000000000000000000000000000000000000000000000","e5c3b8e30fd2d8e6239b17b44bd23bbd","fffffffffffffffffffffffc00000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "94","0000000000000000000000000000000000000000000000000000000000000000","1ac1f7102c59933e8b2ddc3f14e94baa","fffffffffffffffffffffffe00000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "95","0000000000000000000000000000000000000000000000000000000000000000","21d9ba49f276b45f11af8fc71a088e3d","ffffffffffffffffffffffff00000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "96","0000000000000000000000000000000000000000000000000000000000000000","649f1cddc3792b4638635a392bc9bade","ffffffffffffffffffffffff80000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "97","0000000000000000000000000000000000000000000000000000000000000000","e2775e4b59c1bc2e31a2078c11b5a08c","ffffffffffffffffffffffffc0000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "98","0000000000000000000000000000000000000000000000000000000000000000","2be1fae5048a25582a679ca10905eb80","ffffffffffffffffffffffffe0000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "99","0000000000000000000000000000000000000000000000000000000000000000","da86f292c6f41ea34fb2068df75ecc29","fffffffffffffffffffffffff0000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "100","0000000000000000000000000000000000000000000000000000000000000000","220df19f85d69b1b562fa69a3c5beca5","fffffffffffffffffffffffff8000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "101","0000000000000000000000000000000000000000000000000000000000000000","1f11d5d0355e0b556ccdb6c7f5083b4d","fffffffffffffffffffffffffc000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "102","0000000000000000000000000000000000000000000000000000000000000000","62526b78be79cb384633c91f83b4151b","fffffffffffffffffffffffffe000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "103","0000000000000000000000000000000000000000000000000000000000000000","90ddbcb950843592dd47bbef00fdc876","ffffffffffffffffffffffffff000000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "104","0000000000000000000000000000000000000000000000000000000000000000","2fd0e41c5b8402277354a7391d2618e2","ffffffffffffffffffffffffff800000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "105","0000000000000000000000000000000000000000000000000000000000000000","3cdf13e72dee4c581bafec70b85f9660","ffffffffffffffffffffffffffc00000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "106","0000000000000000000000000000000000000000000000000000000000000000","afa2ffc137577092e2b654fa199d2c43","ffffffffffffffffffffffffffe00000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "107","0000000000000000000000000000000000000000000000000000000000000000","8d683ee63e60d208e343ce48dbc44cac","fffffffffffffffffffffffffff00000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "108","0000000000000000000000000000000000000000000000000000000000000000","705a4ef8ba2133729c20185c3d3a4763","fffffffffffffffffffffffffff80000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "109","0000000000000000000000000000000000000000000000000000000000000000","0861a861c3db4e94194211b77ed761b9","fffffffffffffffffffffffffffc0000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "110","0000000000000000000000000000000000000000000000000000000000000000","4b00c27e8b26da7eab9d3a88dec8b031","fffffffffffffffffffffffffffe0000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "111","0000000000000000000000000000000000000000000000000000000000000000","5f397bf03084820cc8810d52e5b666e9","ffffffffffffffffffffffffffff0000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "112","0000000000000000000000000000000000000000000000000000000000000000","63fafabb72c07bfbd3ddc9b1203104b8","ffffffffffffffffffffffffffff8000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "113","0000000000000000000000000000000000000000000000000000000000000000","683e2140585b18452dd4ffbb93c95df9","ffffffffffffffffffffffffffffc000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "114","0000000000000000000000000000000000000000000000000000000000000000","286894e48e537f8763b56707d7d155c8","ffffffffffffffffffffffffffffe000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "115","0000000000000000000000000000000000000000000000000000000000000000","a423deabc173dcf7e2c4c53e77d37cd1","fffffffffffffffffffffffffffff000", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "116","0000000000000000000000000000000000000000000000000000000000000000","eb8168313e1cfdfdb5e986d5429cf172","fffffffffffffffffffffffffffff800", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "117","0000000000000000000000000000000000000000000000000000000000000000","27127daafc9accd2fb334ec3eba52323","fffffffffffffffffffffffffffffc00", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "118","0000000000000000000000000000000000000000000000000000000000000000","ee0715b96f72e3f7a22a5064fc592f4c","fffffffffffffffffffffffffffffe00", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "119","0000000000000000000000000000000000000000000000000000000000000000","29ee526770f2a11dcfa989d1ce88830f","ffffffffffffffffffffffffffffff00", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "120","0000000000000000000000000000000000000000000000000000000000000000","0493370e054b09871130fe49af730a5a","ffffffffffffffffffffffffffffff80", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "121","0000000000000000000000000000000000000000000000000000000000000000","9b7b940f6c509f9e44a4ee140448ee46","ffffffffffffffffffffffffffffffc0", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "122","0000000000000000000000000000000000000000000000000000000000000000","2915be4a1ecfdcbe3e023811a12bb6c7","ffffffffffffffffffffffffffffffe0", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "123","0000000000000000000000000000000000000000000000000000000000000000","7240e524bc51d8c4d440b1be55d1062c","fffffffffffffffffffffffffffffff0", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "124","0000000000000000000000000000000000000000000000000000000000000000","da63039d38cb4612b2dc36ba26684b93","fffffffffffffffffffffffffffffff8", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "125","0000000000000000000000000000000000000000000000000000000000000000","0f59cb5a4b522e2ac56c1a64f558ad9a","fffffffffffffffffffffffffffffffc", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "126","0000000000000000000000000000000000000000000000000000000000000000","7bfe9d876c6d63c1d035da8fe21c409d","fffffffffffffffffffffffffffffffe", true);
    aes_test(maid_aes_256, "ECBVarTxt256.rsp", "127","0000000000000000000000000000000000000000000000000000000000000000","acdace8078a32b1a182bfa4987ca1347","ffffffffffffffffffffffffffffffff", true);
}

static void
aes_tests(void)
{
    aes_test_gfsbox_128();
    aes_test_keysbox_128();
    aes_test_varkey_128();
    aes_test_vartxt_128();

    aes_test_gfsbox_192();
    aes_test_keysbox_192();
    aes_test_varkey_192();
    aes_test_vartxt_192();

    aes_test_gfsbox_256();
    aes_test_keysbox_256();
    aes_test_varkey_256();
    aes_test_vartxt_256();
}

/* Chacha20 RFC7539 vectors */

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
            fail_test(file, num, false);
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
    chacha_test("RFC7539-2.4.2", "0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "000000000000004a00000000", 1, "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                                               "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                                               "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                                               "637265656e20776f756c642062652069742e",
                                               "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                                               "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                                               "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                                               "5af90bbf74a35be6b40b8eedf2785e42874d");

    chacha_test("RFC7539-Appendix.A.1", "1", "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000", 0, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                                               "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    chacha_test("RFC7539-Appendix.A.1", "2", "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000", 1, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
                                               "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
    chacha_test("RFC7539-Appendix.A.1", "3", "0000000000000000000000000000000000000000000000000000000000000001",
                "000000000000000000000000", 1, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
                                               "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");
    chacha_test("RFC7539-Appendix.A.1", "4", "00ff000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000", 2, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
                                               "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");
    chacha_test("RFC7539-Appendix.A.1", "5", "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000002", 0, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
                                               "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");

    chacha_test("RFC7539-Appendix.A.2", "1", "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000", 0, "0000000000000000000000000000000000000000000000000000000000000000"
                                               "0000000000000000000000000000000000000000000000000000000000000000",
                                               "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                                               "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    chacha_test("RFC7539-Appendix.A.2", "2", "0000000000000000000000000000000000000000000000000000000000000001",
                "000000000000000000000002", 1, "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
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
    chacha_test("RFC7539-Appendix.A.2", "3", "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                "000000000000000000000002", 42, "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
                                                "7665730a446964206779726520616e642067696d626c6520696e207468652077"
                                                "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
                                                "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
                                                "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
                                                "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
                                                "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
                                                "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");
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
chacha20poly1305_vec1(void)
{
    char *data = "Ladies and Gentlemen of the class of '99: "
                 "If I could offer you only one tip for the future, "
                 "sunscreen would be it.";
    u8 ad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};

    u8 key[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    u8 nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
                    0x44, 0x45, 0x46, 0x47};

    u8 cipher[] = {0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
                   0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
                   0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
                   0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
                   0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
                   0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
                   0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                   0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
                   0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
                   0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
                   0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
                   0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
                   0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
                   0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                   0x61, 0x16};
    u8 tag[] = {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91};

    return aead_test(maid_chacha20poly1305, key, nonce,
                     ad, sizeof(ad), (u8*)data, strlen(data),
                     cipher, tag, sizeof(tag));
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
    return failures == 0 && aes_gcm_vec1() && chacha20poly1305_vec1() ?
           EXIT_SUCCESS : EXIT_FAILURE;
}
