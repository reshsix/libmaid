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
#include <maid/mem.h>
#include <maid/pub.h>

#include <maid/keygen.h>

static size_t
maid_keygen_rsa_attempt(size_t bits, maid_mp_word **output, maid_rng *g)
{
    size_t ret = maid_mp_words(bits);

    for (u8 i = 0; i < 8; i++)
    {
        output[i] = calloc(ret, sizeof(maid_mp_word));
        if (!output[i])
        {
            ret = 0;
            break;
        }
    }

    if (ret)
    {
        /* Public exponent, hardcoded as 65537 */
        maid_mp_mov(ret, output[1], NULL);
        output[1][0] = 65537;

        /* Prime generation */
        maid_mp_mov(ret, output[3], NULL);
        maid_mp_mov(ret, output[4], NULL);
        maid_mp_prime(ret, output[3], g, bits / 2, 256);
        maid_mp_prime(ret, output[4], g, bits / 2, 256);

        /* Modulo */
        maid_mp_mov(ret, output[0], output[3]);
        maid_mp_mul(ret, output[0], output[4]);

        /* Totient, using Euler's for the moment */
        maid_mp_word tot[ret];
        maid_mp_word pm1[ret];
        maid_mp_word qm1[ret];
        maid_mp_word tmp[ret];
        maid_mp_mov(ret, tmp, NULL);
        tmp[0] = 1;

        maid_mp_mov(ret, pm1, output[3]);
        maid_mp_sub(ret, pm1, tmp);
        maid_mp_mov(ret, qm1, output[4]);
        maid_mp_sub(ret, qm1, tmp);
        maid_mp_mov(ret, tot, pm1);
        maid_mp_mul(ret, tot, qm1);

        /* Private exponent */
        maid_mp_mov(ret, output[2], output[1]);
        maid_mp_invmod(ret, output[2], tot);

        /* CRT Exponents */
        maid_mp_mov(ret, output[5], output[2]);
        maid_mp_mod(ret, output[5], pm1);
        maid_mp_mov(ret, output[6], output[2]);
        maid_mp_mod(ret, output[6], qm1);

        /* CRT Coefficient */
        maid_mp_mov(ret, output[7], output[4]);
        maid_mp_invmod(ret, output[7], output[3]);

        /* Cleanup */
        maid_mem_clear(tot, sizeof(tot));
        maid_mem_clear(pm1, sizeof(pm1));
        maid_mem_clear(qm1, sizeof(qm1));
        maid_mem_clear(tmp, sizeof(tmp));
    }

    return ret;
}

extern size_t
maid_keygen_rsa(size_t bits, maid_mp_word **output, maid_rng *g)
{
    size_t ret = 0;

    if (bits && bits >= 64 && bits % 64 == 0 && output)
    {
        while (ret == 0)
        {
            ret = maid_keygen_rsa_attempt(bits, output, g);
            if (ret)
            {
                u8 test[bits / 8];
                test[0] = 0x02;
                for (size_t i = 1; i < bits / 8; i++)
                   test[i] = 0x00;

                struct maid_rsa_key k1 = {.exponent = output[1],
                                          .modulo   = output[0]};
                struct maid_rsa_key k2 = {.exponent = output[2],
                                          .modulo   = output[0]};

                maid_pub *pub = maid_pub_new(maid_rsa_public,  &k1, bits);
                maid_pub *prv = maid_pub_new(maid_rsa_private, &k2, bits);

                if (pub && prv)
                {
                    maid_pub_apply(pub, test);
                    maid_pub_apply(prv, test);

                    if (test[0] != 0x02)
                        ret = 0;

                    for (size_t i = 1; i < bits / 8; i++)
                    {
                        if (test[i] != 0x00)
                        {
                            ret = 0;
                            break;
                        }
                    }
                }
                else
                    ret = 0;

                maid_pub_del(pub);
                maid_pub_del(prv);

                maid_mem_clear(test, sizeof(test));
            }

            if (!ret)
            {
                for (u8 i = 0; i < 8; i++)
                {
                    free(output[i]);
                    output[i] = NULL;
                }
            }
        }
    }

    return ret;
}
