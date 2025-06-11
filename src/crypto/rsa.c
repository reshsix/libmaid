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

#include <maid/mp.h>
#include <maid/mem.h>

#include <maid/pub.h>

enum
{
    RSA_PUBLIC, RSA_PRIVATE, RSA_PRIVATE_CRT
};

struct rsa
{
    size_t bits;
    u8 version;

    size_t words;
    struct maid_rsa_key_full key;
};

extern void *
rsa_del(void *rsa)
{
    if (rsa)
    {
        struct rsa *r = rsa;
        size_t size = r->words * sizeof(maid_mp_word);

        maid_mem_clear(r->key.encryption,  size);
        maid_mem_clear(r->key.decryption,  size);
        maid_mem_clear(r->key.modulo,      size);
        maid_mem_clear(r->key.prime1,      size);
        maid_mem_clear(r->key.prime2,      size);
        maid_mem_clear(r->key.exponent1,   size);
        maid_mem_clear(r->key.exponent2,   size);
        maid_mem_clear(r->key.coefficient, size);

        free(r->key.encryption);
        free(r->key.decryption);
        free(r->key.modulo);
        free(r->key.prime1);
        free(r->key.prime2);
        free(r->key.exponent1);
        free(r->key.exponent2);
        free(r->key.coefficient);

        maid_mem_clear(r, sizeof(struct rsa));
    }
    free(rsa);

    return NULL;
}

extern void
rsa_renew(void *rsa, const void *key)
{
    if (rsa && key)
    {
        struct rsa *r = rsa;

        switch (r->version)
        {
            case RSA_PUBLIC:;
                const struct maid_rsa_key *k = key;
                maid_mp_mov(r->words, r->key.encryption, k->exponent);
                maid_mp_mov(r->words, r->key.modulo,     k->modulo);
                break;

            case RSA_PRIVATE:;
                const struct maid_rsa_key *k2 = key;
                maid_mp_mov(r->words, r->key.decryption, k2->exponent);
                maid_mp_mov(r->words, r->key.modulo,     k2->modulo);
                break;

            case RSA_PRIVATE_CRT:;
                const struct maid_rsa_key_full *k3 = key;
                maid_mp_mov(r->words, r->key.encryption,  k3->encryption);
                maid_mp_mov(r->words, r->key.decryption,  k3->decryption);
                maid_mp_mov(r->words, r->key.modulo,      k3->modulo);
                maid_mp_mov(r->words, r->key.prime1,      k3->prime1);
                maid_mp_mov(r->words, r->key.prime2,      k3->prime2);
                maid_mp_mov(r->words, r->key.exponent1,   k3->exponent1);
                maid_mp_mov(r->words, r->key.exponent2,   k3->exponent2);
                maid_mp_mov(r->words, r->key.coefficient, k3->coefficient);
                break;

            default:
                break;
        }
    }
}

extern void *
rsa_new(u8 version, const void *key, size_t bits)
{
    struct rsa *ret = NULL;
    if (bits && bits % (sizeof(maid_mp_word) * 8) == 0)
        ret = calloc(1, sizeof(struct rsa));

    if (ret)
    {
        ret->bits = bits;
        ret->version = version;

        ret->words = maid_mp_words(ret->bits);
        size_t size = ret->words * sizeof(maid_mp_word);
        switch (ret->version)
        {
            case RSA_PUBLIC:;
                if ((ret->key.encryption = calloc(1, size)) &&
                    (ret->key.modulo     = calloc(1, size)))
                    rsa_renew(ret, key);
                else
                    ret = rsa_del(ret);
                break;

            case RSA_PRIVATE:;
                if ((ret->key.decryption = calloc(1, size)) &&
                    (ret->key.modulo     = calloc(1, size)))
                    rsa_renew(ret, key);
                else
                    ret = rsa_del(ret);
                break;

            case RSA_PRIVATE_CRT:;
                if ((ret->key.encryption  = calloc(1, size)) &&
                    (ret->key.decryption  = calloc(1, size)) &&
                    (ret->key.modulo      = calloc(1, size)) &&
                    (ret->key.prime1      = calloc(1, size)) &&
                    (ret->key.prime2      = calloc(1, size)) &&
                    (ret->key.exponent1   = calloc(1, size)) &&
                    (ret->key.exponent2   = calloc(1, size)) &&
                    (ret->key.coefficient = calloc(1, size)))
                    rsa_renew(ret, key);
                else
                    ret = rsa_del(ret);
                break;

            default:
                ret = rsa_del(ret);
                break;
        }
    }

    return ret;
}

extern void
rsa_apply(void *rsa, u8 *buffer)
{
    if (rsa && buffer)
    {
        struct rsa *r = rsa;

        maid_mp_word buf[r->words];
        maid_mp_read(r->words, buf, buffer, true);

        if (r->version == RSA_PUBLIC)
            maid_mp_expmod2(r->words, buf, r->key.encryption,
                            r->key.modulo, false);
        else if (r->version == RSA_PRIVATE)
            maid_mp_expmod2(r->words, buf, r->key.decryption,
                            r->key.modulo, true);
        else if (r->version == RSA_PRIVATE_CRT)
        {
            maid_mp_word org[r->words];
            maid_mp_mov(r->words, org, buf);

            maid_mp_word bp[r->words];
            maid_mp_word bq[r->words];
            maid_mp_mov(r->words, bp, buf);
            maid_mp_mov(r->words, bq, buf);
            maid_mp_mod(r->words, bp, r->key.prime1);
            maid_mp_mod(r->words, bq, r->key.prime2);

            maid_mp_expmod2(r->words / 2, bp, r->key.exponent1,
                            r->key.prime1, true);
            maid_mp_expmod2(r->words / 2, bq, r->key.exponent2,
                            r->key.prime2, true);

            maid_mp_submod(r->words, bp, bq, r->key.prime1);
            maid_mp_mulmod(r->words, bp, r->key.coefficient,
                           r->key.prime1);
            maid_mp_mulmod(r->words, bp, r->key.prime2, r->key.modulo);

            maid_mp_add(r->words, bp, bq);
            maid_mp_mod(r->words, bp, r->key.modulo);

            /* Tests against fault attacks */
            maid_mp_mov(r->words, buf, bp);
            maid_mp_expmod2(r->words, buf, r->key.encryption,
                            r->key.modulo, false);

            if (maid_mp_cmp(r->words, org, buf) == 0)
                maid_mp_mov(r->words, buf, bp);
            else
            {
                maid_mp_mov(r->words, buf, org);
                maid_mp_expmod2(r->words, buf, r->key.decryption,
                                r->key.modulo, true);
            }

            maid_mem_clear(org, sizeof(org));
            maid_mem_clear(bp,  sizeof(bp));
            maid_mem_clear(bq,  sizeof(bq));
        }

        maid_mp_write(r->words, buf, buffer, true);
        maid_mem_clear(buf, sizeof(buf));
    }
}

/* Maid PUB definitions */

const struct maid_pub_def maid_rsa_public =
{
    .new   = rsa_new,   .del   = rsa_del,
    .renew = rsa_renew, .apply = rsa_apply,
    .version = RSA_PUBLIC
};

const struct maid_pub_def maid_rsa_private =
{
    .new   = rsa_new,   .del   = rsa_del,
    .renew = rsa_renew, .apply = rsa_apply,
    .version = RSA_PRIVATE
};

const struct maid_pub_def maid_rsa_private_crt =
{
    .new   = rsa_new,   .del   = rsa_del,
    .renew = rsa_renew, .apply = rsa_apply,
    .version = RSA_PRIVATE_CRT
};
