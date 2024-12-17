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
    RSA_PUBLIC, RSA_PRIVATE
};

struct rsa
{
    size_t bits;
    bool private;

    size_t words;

    struct maid_rsa_key key;
    maid_mp_word *buf;
    maid_mp_word *tmp;
};

extern void *
rsa_del(void *rsa)
{
    if (rsa)
    {
        struct rsa *r = rsa;
        size_t size = r->words * sizeof(maid_mp_word);

        maid_mem_clear(r->key.exponent, size);
        maid_mem_clear(r->key.modulo,   size);
        maid_mem_clear(r->buf, size);
        maid_mem_clear(r->tmp, size * 49);

        free(r->key.exponent);
        free(r->key.modulo);
        free(r->buf);
        free(r->tmp);

        maid_mem_clear(r, sizeof(struct rsa));
    }
    free(rsa);

    return NULL;
}

extern void *
rsa_new(const struct maid_pub_def *self, const void *key, size_t bits)
{
    struct rsa *ret = NULL;
    if (bits && bits % (sizeof(maid_mp_word) * 8) == 0)
        ret = calloc(1, sizeof(struct rsa));

    const struct maid_rsa_key *k = key;
    if (ret)
    {
        ret->bits = bits;
        ret->private = (self != &maid_rsa_public);

        ret->words = maid_mp_words(ret->bits);
        size_t size = ret->words * sizeof(maid_mp_word);

        ret->key.exponent = calloc(1, size);
        ret->key.modulo   = calloc(1, size);

        ret->buf = calloc(1,  size);
        ret->tmp = calloc(49, size);

        if (ret->buf && ret->tmp && ret->key.exponent && ret->key.modulo)
        {
            maid_mp_mov(ret->words, ret->key.exponent, k->exponent);
            maid_mp_mov(ret->words, ret->key.modulo,   k->modulo);
        }
        else
            ret = rsa_del(ret);
    }

    return ret;
}

extern void
rsa_renew(void *rsa, const void *key)
{
    if (rsa && key)
    {
        struct rsa *r = rsa;

        const struct maid_rsa_key *k = key;
        maid_mp_mov(r->words, r->key.exponent, k->exponent);
        maid_mp_mov(r->words, r->key.modulo,   k->modulo);
    }
}

extern void
rsa_apply(void *rsa, u8 *buffer)
{
    if (rsa && buffer)
    {
        struct rsa *r = rsa;

        maid_mp_read(r->words, r->buf, buffer, true);
        maid_mp_expmod2(r->words, r->buf, r->key.exponent,
                        r->key.modulo, r->tmp, r->private);
        maid_mp_write(r->words, r->buf, buffer, true);
    }
}

/* Maid PUB definitions */

const struct maid_pub_def maid_rsa_public =
{
    .new   = rsa_new,   .del   = rsa_del,
    .renew = rsa_renew, .apply = rsa_apply,
    .self = &maid_rsa_public
};

const struct maid_pub_def maid_rsa_private =
{
    .new   = rsa_new,   .del   = rsa_del,
    .renew = rsa_renew, .apply = rsa_apply,
    .self = &maid_rsa_private
};
