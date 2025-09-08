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
#include <maid/asn1.h>

#include <maid/rsa.h>

struct maid_rsa_public
{
    size_t words;

    maid_mp_word *modulo;
    maid_mp_word *encryption;
};

struct maid_rsa_private
{
    size_t words;

    maid_mp_word *modulo;
    maid_mp_word *encryption;
    maid_mp_word *decryption;

    maid_mp_word *prime1;
    maid_mp_word *prime2;

    maid_mp_word *exponent1;
    maid_mp_word *exponent2;
    maid_mp_word *coefficient;
};

extern struct maid_rsa_public *
maid_rsa_del(struct maid_rsa_public *k)
{
    if (k)
    {
        if (k->modulo)
            maid_mp_mov(k->words, k->modulo,     NULL);
        if (k->encryption)
            maid_mp_mov(k->words, k->encryption, NULL);
        free(k->modulo);
        free(k->encryption);

        k->words = 0;
    }
    free(k);

    return NULL;
}

extern struct maid_rsa_private *
maid_rsa_del2(struct maid_rsa_private *k)
{
    if (k)
    {
        if (k->modulo)
            maid_mp_mov(k->words, k->modulo,     NULL);
        if (k->encryption)
            maid_mp_mov(k->words, k->encryption, NULL);
        if (k->decryption)
            maid_mp_mov(k->words, k->decryption, NULL);
        free(k->modulo);
        free(k->encryption);
        free(k->decryption);

        if (k->prime1)
            maid_mp_mov(k->words, k->prime1, NULL);
        if (k->prime2)
            maid_mp_mov(k->words, k->prime2, NULL);
        free(k->prime1);
        free(k->prime2);

        if (k->exponent1)
            maid_mp_mov(k->words, k->exponent1, NULL);
        if (k->exponent2)
            maid_mp_mov(k->words, k->exponent2, NULL);
        if (k->coefficient)
            maid_mp_mov(k->words, k->coefficient, NULL);
        free(k->exponent1);
        free(k->exponent2);
        free(k->coefficient);

        k->words = 0;
    }
    free(k);

    return NULL;
}

extern struct maid_rsa_public *
maid_rsa_new(const u8 *data, size_t size)
{
    /* PKCS1 public key */

    struct maid_rsa_public *ret = calloc(1, sizeof(struct maid_rsa_public));

    bool success = false;
    if (ret && data && maid_asn1_check(0x30, data, size))
    {
        size_t remain = size;
        u8 *current = maid_asn1_enter(data, &remain);

        ret->modulo = maid_asn1_from_integer(current, remain, &(ret->words));
        if (ret->modulo)
        {
            current = maid_asn1_advance(current, &remain);
            ret->encryption = maid_asn1_from_integer(current, remain,
                                                              &(ret->words));
            if (ret->encryption)
            {
                current = maid_asn1_advance(current, &remain);
                if (remain == 0)
                    success = true;
            }
        }
    }

    if (!success)
        ret = maid_rsa_del(ret);

    return ret;
}

extern struct maid_rsa_private *
maid_rsa_new2(const u8 *data, size_t size)
{
    /* PKCS1 private key */

    struct maid_rsa_private *ret = calloc(1, sizeof(struct maid_rsa_private));

    bool success = false;
    if (ret && data && maid_asn1_check(0x30, data, size))
    {
        size_t remain = size;
        u8 *current = maid_asn1_enter(data, &remain);

        if (maid_asn1_check(0x02, current, remain) &&
            current[1] == 0x01 && current[2] == 0x00)
        {
            success = true;
            maid_mp_word *values[8] = {NULL};

            current = maid_asn1_advance(current, &remain);
            for (u8 i = 0; i < 8; i++)
            {
                values[i] = maid_asn1_from_integer(current, remain,
                                                            &(ret->words));
                if (values[i])
                    current = maid_asn1_advance(current, &remain);
                else
                {
                    success = false;
                    break;
                }
            }
            if (remain != 0)
                success = false;

            if (success)
            {
                ret->modulo      = values[0];
                ret->encryption  = values[1];
                ret->decryption  = values[2];
                ret->prime1      = values[3];
                ret->prime2      = values[4];
                ret->exponent1   = values[5];
                ret->exponent2   = values[6];
                ret->coefficient = values[7];
            }
        }
    }

    if (!success)
        ret = maid_rsa_del2(ret);

    return ret;
}

extern size_t
maid_rsa_size(const struct maid_rsa_public *k)
{
    return (k) ? k->words : 0;
}

extern size_t
maid_rsa_size2(const struct maid_rsa_private *k)
{
    return (k) ? k->words : 0;
}

extern u8 *
maid_rsa_export(const struct maid_rsa_public *k, size_t *size)
{
    u8 *ret = NULL;

    if (k)
    {
        maid_mp_word *input[2] = {k->modulo, k->encryption};
        size_t sizes[2] = {0};

        size_t seq_s = 0;
        for (size_t i = 0; i < 2; i++)
        {
            sizes[i] = maid_asn1_measure_integer(k->words, input[i]);
            seq_s += maid_asn1_measure_tag(sizes[i]);
        }

        if (seq_s)
        {
            *size = maid_asn1_measure_tag(seq_s);
            ret = calloc(1, *size);
        }

        if (ret)
        {
            u8 *output = maid_asn1_to_tag(ret, 0x30, seq_s);
            for (size_t i = 0; i < 2; i++)
            {
                output = maid_asn1_to_tag(output, 0x02, sizes[i]);
                output = maid_asn1_to_integer(output, k->words,
                                              input[i], sizes[i]);
            }
        }

        maid_mem_clear(sizes, sizeof(sizes));
    }

    return ret;
}

extern u8 *
maid_rsa_export2(const struct maid_rsa_private *k, size_t *size)
{
    u8 *ret = NULL;

    if (k)
    {
        maid_mp_word *input[8] = {k->modulo,    k->encryption, k->decryption,
                                  k->prime1,    k->prime2,
                                  k->exponent1, k->exponent2, k->coefficient};
        size_t sizes[8] = {0};

        size_t seq_s = 0;
        for (size_t i = 0; i < 8; i++)
        {
            sizes[i] = maid_asn1_measure_integer(k->words, input[i]);
            seq_s += maid_asn1_measure_tag(sizes[i]);
        }

        if (seq_s)
        {
            seq_s += 3;

            *size = maid_asn1_measure_tag(seq_s);
            ret = calloc(1, *size);
        }

        if (ret)
        {
            u8 *output = maid_asn1_to_tag(ret, 0x30, seq_s);

            maid_mp_word zero = 0;
            output = maid_asn1_to_tag(output, 0x02, 1);
            output = maid_asn1_to_integer(output, 1, &zero, 1);

            for (size_t i = 0; i < 8; i++)
            {
                output = maid_asn1_to_tag(output, 0x02, sizes[i]);
                output = maid_asn1_to_integer(output, k->words,
                                              input[i], sizes[i]);
            }
        }

        maid_mem_clear(sizes, sizeof(sizes));
    }

    return ret;
}

extern bool
maid_rsa_encrypt(const struct maid_rsa_public *k, maid_mp_word *s)
{
    bool ret = true;

    if (k && s)
        maid_mp_expmod2(k->words, s, k->encryption, k->modulo, false);
    else
        ret = false;

    return ret;
}

extern bool
maid_rsa_decrypt(const struct maid_rsa_private *k, maid_mp_word *s)
{
    bool ret = true;

    if (k && s)
    {
        maid_mp_word org[k->words];
        maid_mp_mov(k->words, org, s);

        maid_mp_word bp[k->words];
        maid_mp_word bq[k->words];
        maid_mp_mov(k->words, bp, s);
        maid_mp_mov(k->words, bq, s);
        maid_mp_mod(k->words, bp, k->prime1);
        maid_mp_mod(k->words, bq, k->prime2);

        maid_mp_expmod2(k->words / 2, bp, k->exponent1, k->prime1, true);
        maid_mp_expmod2(k->words / 2, bq, k->exponent2, k->prime2, true);

        maid_mp_submod(k->words, bp, bq, k->prime1);
        maid_mp_mulmod(k->words, bp, k->coefficient, k->prime1);
        maid_mp_mulmod(k->words, bp, k->prime2, k->modulo);

        maid_mp_add(k->words, bp, bq);
        maid_mp_mod(k->words, bp, k->modulo);

        /* Tests against fault attacks */
        maid_mp_mov(k->words, s, bp);
        maid_mp_expmod2(k->words, s, k->encryption, k->modulo, false);

        if (maid_mp_cmp(k->words, org, s) == 0)
            maid_mp_mov(k->words, s, bp);
        else
        {
            maid_mp_mov(k->words, s, org);
            maid_mp_expmod2(k->words, s, k->decryption, k->modulo, true);
        }

        maid_mem_clear(org, sizeof(org));
        maid_mem_clear(bp,  sizeof(bp));
        maid_mem_clear(bq,  sizeof(bq));
    }
    else
        ret = false;

    return ret;
}

static bool
maid_rsa_keygen_attempt(size_t words, size_t bits, u64 exponent,
                        maid_mp_word **output, maid_rng *g)
{
    bool ret = false;

    /* Public exponent */
    maid_mp_mov(words, output[1], NULL);
    output[1][0] = exponent;

    /* Prime generation */
    maid_mp_mov(words,   output[3], NULL);
    maid_mp_mov(words,   output[4], NULL);
    maid_mp_prime(words, output[3], g, bits / 2, 256);
    maid_mp_prime(words, output[4], g, bits / 2, 256);

    /* Modulo */
    maid_mp_mov(words, output[0], output[3]);
    maid_mp_mul(words, output[0], output[4]);

    /* Totient, using Euler's for the moment */
    maid_mp_word tot[words];
    maid_mp_word pm1[words];
    maid_mp_word qm1[words];
    maid_mp_word tmp[words];
    maid_mp_mov(words, tmp, NULL);
    tmp[0] = 1;

    maid_mp_mov(words, pm1, output[3]);
    maid_mp_sub(words, pm1, tmp);
    maid_mp_mov(words, qm1, output[4]);
    maid_mp_sub(words, qm1, tmp);
    maid_mp_mov(words, tot, pm1);
    maid_mp_mul(words, tot, qm1);

    /* Private exponent */
    maid_mp_mov(words, output[2], output[1]);
    if (maid_mp_invmod(words, output[2], tot))
    {
        /* CRT Exponents */
        maid_mp_mov(words, output[5], output[2]);
        maid_mp_mod(words, output[5], pm1);
        maid_mp_mov(words, output[6], output[2]);
        maid_mp_mod(words, output[6], qm1);

        /* CRT Coefficient */
        maid_mp_mov(words, output[7], output[4]);
        ret = maid_mp_invmod(words, output[7], output[3]);
    }

    /* Cleanup */
    maid_mem_clear(tot, sizeof(tot));
    maid_mem_clear(pm1, sizeof(pm1));
    maid_mem_clear(qm1, sizeof(qm1));
    maid_mem_clear(tmp, sizeof(tmp));

    return ret;
}

extern struct maid_rsa_private *
maid_rsa_keygen(size_t bits, u64 exponent, maid_rng *g)
{
    struct maid_rsa_private *ret = NULL;
    if (bits && bits >= 64 && bits % 64 == 0 && exponent >= 2 && g)
        ret = calloc(1, sizeof(struct maid_rsa_private));

    size_t words = maid_mp_words(bits);
    maid_mp_word *output[8] = {NULL};
    if (ret)
    {
        for (u8 i = 0; i < 8; i++)
        {
            output[i] = calloc(words, sizeof(maid_mp_word));
            if (!output[i])
            {
                for (u8 j = 0; j < i; j++)
                    free(output[j]);

                free(ret);
                ret = NULL;
                break;
            }
        }
    }

    bool success = false;
    while (ret && !success)
    {
        if (maid_rsa_keygen_attempt(words, bits, exponent, output, g))
        {
            ret->words       = words;
            ret->modulo      = output[0];
            ret->encryption  = output[1];
            ret->decryption  = output[2];
            ret->prime1      = output[3];
            ret->prime2      = output[4];
            ret->exponent1   = output[5];
            ret->exponent2   = output[6];
            ret->coefficient = output[7];
            break;
        }
    }

    return ret;
}

extern struct maid_rsa_public *
maid_rsa_pubgen(struct maid_rsa_private *k)
{
    struct maid_rsa_public *ret = NULL;
    if (k)
        ret = calloc(1, sizeof(struct maid_rsa_public));

    if (ret)
    {
        ret->words      = k->words;
        ret->modulo     = calloc(k->words, sizeof(maid_mp_word));
        ret->encryption = calloc(k->words, sizeof(maid_mp_word));
        if (ret->modulo && ret->encryption)
        {
            maid_mp_mov(k->words, ret->modulo,     k->modulo);
            maid_mp_mov(k->words, ret->encryption, k->encryption);
        }
        else
            ret = maid_rsa_del(ret);
    }

    return ret;
}

extern bool
maid_rsa_pair(struct maid_rsa_public *k, struct maid_rsa_private *k2)
{
    bool ret = false;

    if (k && k2 && k->words == k2->words)
    {
        maid_mp_word test[k->words];
        maid_mp_mov(k->words, test, NULL);
        test[0] = 0xcafebabe;

        maid_mp_word test2[k->words];
        maid_mp_mov(k->words, test2, test);
        ret = maid_rsa_encrypt(k, test)               &&
              maid_mp_cmp(k->words, test, test2) != 0 &&
              maid_rsa_decrypt(k2, test)              &&
              maid_mp_cmp(k->words, test, test2) == 0 ;

        maid_mp_mov(k->words, test,  NULL);
        maid_mp_mov(k->words, test2, NULL);
    }

    return ret;
}
