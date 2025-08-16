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

#ifndef MAID_TEST_H
#define MAID_TEST_H

#include <maid/types.h>

u8 maid_test_mem(void);
u8 maid_test_mp(void);

u8 maid_test_aes_ecb(void);
u8 maid_test_aes_ctr(void);
u8 maid_test_aes_gcm(void);
u8 maid_test_chacha(void);
u8 maid_test_poly1305(void);
u8 maid_test_chacha20poly1305(void);
u8 maid_test_ctr_drbg(void);
u8 maid_test_sha1(void);
u8 maid_test_sha2(void);
u8 maid_test_hmac_sha1(void);
u8 maid_test_hmac_sha2(void);

u8 maid_test_rsa(void);
u8 maid_test_edwards25519(void);
u8 maid_test_pkcs1(void);
u8 maid_test_dh(void);

u8 maid_test_pem(void);
u8 maid_test_serial_rsa(void);
u8 maid_test_keygen_rsa(void);

#endif
