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

#include <maid/kdf.h>
#include <maid/mac.h>
#include <maid/mem.h>
#include <maid/hash.h>

#include <internal/kdf.h>
#include <internal/types.h>

/* Maid KDF definition */

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
hkdf_new(const void *params, u8 state_s, u8 digest_s, size_t output_s)
{
    struct hkdf *ret = calloc(1, sizeof(struct hkdf));

    if (ret)
    {
        u8 empty[128] = {0};
        ret->prf      = maid_hmac_sha2((state_s == 128), empty, digest_s);
        ret->hash     = maid_sha2((state_s == 128), digest_s);
        ret->key_s    = state_s;
        ret->digest_s = digest_s;

        if (output_s <= (255 * ret->digest_s))
        {
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

static const struct maid_kdf_def hkdf_sha2_def =
{
    .new     = hkdf_new,
    .del     = hkdf_del,
    .renew   = hkdf_renew,
    .hash    = hkdf_hash,
};

extern maid_kdf *
maid_hkdf_sha2(const struct maid_hkdf_params *p,
               bool bits64, u8 digest_s, size_t output_s)
{
    return maid_kdf_new(&hkdf_sha2_def, p, (bits64) ? 128 : 64,
                        digest_s, output_s);
}
