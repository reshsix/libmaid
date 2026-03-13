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

#include <maid/test.h>

#include <internal/types.h>

extern int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    u32 fails = 0;

    #define TEST(name) \
        printf("%s(): ", #name); \
        u16 name##_fails = name(); \
        if (!name##_fails) \
            printf("success\n"); \
        else \
            printf("failed %u %s\n", name##_fails, \
                   (name##_fails == 1) ? "test" : "tests"); \
        fails += name##_fails;

    TEST(maid_test_mem)
    TEST(maid_test_mp)
    printf("\n");
    TEST(maid_test_1305)
    TEST(maid_test_25519)
    TEST(maid_test_order25519)
    printf("\n");
    TEST(maid_test_chacha20)
    TEST(maid_test_poly1305)
    TEST(maid_test_chacha20poly1305)
    printf("\n");
    TEST(maid_test_chacha20rng);
    printf("\n");
    TEST(maid_test_blake2)
    TEST(maid_test_blake2k)
    printf("\n");
    TEST(maid_test_sha2)
    TEST(maid_test_hmac_sha2)
    TEST(maid_test_hkdf_sha2)
    printf("\n");
    TEST(maid_test_curve25519)
    TEST(maid_test_edwards25519)
    printf("\n");
    TEST(maid_test_ed25519)
    TEST(maid_test_x25519)

    #undef TEST

    return (fails == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
