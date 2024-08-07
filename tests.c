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

#include <maid/maid.h>

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

    u8 out[128] = {0}, out2[16] = {0};
    maid_crypt2(MAID_ENCRYPT, MAID_CHACHA20POLY1305, key, nonce,
                (u8*)data, strlen(data), ad, sizeof(ad),
                out, sizeof(out), out2);

    u8 out3[128] = {0}, out4[16] = {0};
    maid_crypt2(MAID_DECRYPT, MAID_CHACHA20POLY1305, key, nonce,
                out, strlen(data), ad, sizeof(ad),
                out3, sizeof(out3), out4);

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

    return memcmp(out,  cipher, sizeof(cipher)) == 0 &&
           memcmp(out2, tag,    sizeof(tag))    == 0 &&
           memcmp(out3, data,   strlen(data))   == 0 &&
           memcmp(out4, tag,    sizeof(tag))    == 0 ;
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
    u8 ad[]= {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
              0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
              0xab, 0xad, 0xda, 0xd2};

    u8 key[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    u8 nonce[12] = {0xca, 0xfe, 0xba, 0xbe,
                    0xfa, 0xce, 0xdb, 0xad,
                    0xde, 0xca, 0xf8, 0x88};

    u8 out[128] = {0}, out2[16] = {0};
    maid_crypt2(MAID_ENCRYPT, MAID_AES_GCM, key, nonce,
                data, sizeof(data), ad, sizeof(ad),
                out, sizeof(out), out2);

    u8 out3[128] = {0}, out4[16] = {0};
    maid_crypt2(MAID_DECRYPT, MAID_AES_GCM, key, nonce,
                out, sizeof(data), ad, sizeof(ad),
                out3, sizeof(out3), out4);

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

    return memcmp(out,  cipher, sizeof(cipher)) == 0 &&
           memcmp(out2, tag,    sizeof(tag))    == 0 &&
           memcmp(out3, data,   sizeof(data))   == 0 &&
           memcmp(out4, tag,    sizeof(tag))    == 0 ;
}

extern int
main(void)
{
    return aes_gcm_vec1() && chacha20poly1305_vec1() ?
           EXIT_SUCCESS : EXIT_FAILURE;
}
