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

#include <maid/mac.h>
#include <maid/mem.h>
#include <maid/hash.h>

#include <maid/kdf.h>

/* Maid KDF definition */

enum
{
    SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256
};

struct hkdf
{
    struct maid_hkdf_params prm;
    size_t output_s;

    maid_mac  *prf;
    maid_hash *hash;
    size_t key_s, digest_s;
};

static void *
hkdf_del(void *ctx)
{
    if (ctx)
    {
        struct hkdf *p = ctx;
        maid_mac_del(p->prf);
        maid_hash_del(p->hash);

        maid_mem_clear(ctx, sizeof(struct hkdf));
    }
    free(ctx);

    return NULL;
}

static void *
hkdf_new(u8 version, const void *params, size_t output_s)
{
    struct hkdf *ret = calloc(1, sizeof(struct hkdf));

    if (ret)
    {
        const struct maid_mac_def  *mdef = NULL;
        const struct maid_hash_def *hdef = NULL;

        switch (version)
        {
            case SHA224:
                mdef = &maid_hmac_sha224;
                hdef = &maid_sha224;
                ret->key_s    = 64;
                ret->digest_s = 28;
                break;
            case SHA256:
                mdef = &maid_hmac_sha256;
                hdef = &maid_sha256;
                ret->key_s    = 64;
                ret->digest_s = 32;
                break;
            case SHA384:
                mdef = &maid_hmac_sha384;
                hdef = &maid_sha384;
                ret->key_s    = 128;
                ret->digest_s = 48;
                break;
            case SHA512:
                mdef = &maid_hmac_sha512;
                hdef = &maid_sha512;
                ret->key_s    = 128;
                ret->digest_s = 64;
                break;
            case SHA512_224:
                mdef = &maid_hmac_sha512_224;
                hdef = &maid_sha512_224;
                ret->key_s    = 128;
                ret->digest_s = 28;
                break;
            case SHA512_256:
                mdef = &maid_hmac_sha512_256;
                hdef = &maid_sha512_256;
                ret->key_s    = 128;
                ret->digest_s = 32;
                break;
        }

        if (output_s <= (255 * ret->digest_s))
        {
            u8 empty[128] = {0};
            ret->prf  = maid_mac_new(*mdef, empty);
            ret->hash = maid_hash_new(*hdef);
            if (ret->prf && ret->hash)
            {
                memcpy(&(ret->prm), params, sizeof(struct maid_hkdf_params));
                ret->output_s = output_s;
            }
            else
                ret = hkdf_del(ret);
        }
        else
            ret = hkdf_del(ret);
    }

    return ret;
}

static void
hkdf_renew(void *ctx, const void *params)
{
    if (ctx && params)
    {
        struct hkdf *p = ctx;
        memcpy(&(p->prm), params, sizeof(struct maid_hkdf_params));
    }
}

static void
hkdf_hash(void *ctx, const u8 *data, size_t data_s,
          const u8 *salt, size_t salt_s, u8 *output)
{
    if (ctx && data && salt && output)
    {
        struct hkdf *p = ctx;
        maid_mem_clear(output, p->output_s);

        /* PRK = HMAC(salt, data) */
        u8 key[p->key_s];
        maid_mem_clear(key, sizeof(key));
        if (salt_s > p->key_s)
        {
            maid_hash_renew(p->hash);
            maid_hash_update(p->hash, salt, salt_s);
            maid_hash_digest(p->hash, key);
        }
        else
            memcpy(key, salt, salt_s);
        maid_mac_renew(p->prf, key);
        maid_mac_update(p->prf, data, data_s);
        maid_mac_digest(p->prf, key);

        /* OKM = HKDF_Expand(PRK, info, output_s) */
        size_t l = p->output_s;
        for (u8 i = 1; l; i++)
        {
            maid_mac_renew(p->prf, key);
            if (i != 1)
                maid_mac_update(p->prf, &(output[p->digest_s * (i - 2)]),
                                p->digest_s);
            maid_mac_update(p->prf, p->prm.info, p->prm.info_s);

            maid_mac_update(p->prf, &i, 1);
            if (l >= p->digest_s)
            {
                maid_mac_digest(p->prf, &(output[p->digest_s * (i - 1)]));
                l -= p->digest_s;
            }
            else
            {
                u8 hash[p->digest_s];
                maid_mac_digest(p->prf, hash);
                memcpy(&(output[p->digest_s * (i - 1)]), hash, l);

                maid_mem_clear(hash, sizeof(hash));
                l = 0;
            }
        }
    }
}

const struct maid_kdf_def maid_hkdf_sha224 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA224
};

const struct maid_kdf_def maid_hkdf_sha256 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA256
};

const struct maid_kdf_def maid_hkdf_sha384 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA384
};

const struct maid_kdf_def maid_hkdf_sha512 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA512
};

const struct maid_kdf_def maid_hkdf_sha512_224 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA512_224
};

const struct maid_kdf_def maid_hkdf_sha512_256 =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
    .version = SHA512_256
};
