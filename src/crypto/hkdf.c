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

#include <maid/kdf.h>
#include <maid/mac.h>
#include <maid/mem.h>
#include <maid/hash.h>

#include <internal/kdf.h>
#include <internal/types.h>

#include <maid/crypto/sha2.h>
#include <maid/crypto/hkdf_sha2.h>
#include <maid/crypto/hmac_sha2.h>

/* Maid KDF definition */

struct hkdf
{
    const u8 *info;
    size_t info_s;

    size_t output_s;
    maid_mac  *prf;
    maid_hash *hash;
    size_t key_s, digest_s;
};

static void *
hkdf_init(void *buffer, u8 state_s, u8 digest_s, size_t output_s)
{
    struct hkdf *ret = buffer;

    ret->key_s    = state_s;
    ret->digest_s = digest_s;

    if (output_s <= (255 * ret->digest_s))
    {
        bool bits64 = (state_s == 128);
        ret->prf  = maid_hmac_sha2(&(ret[1]), bits64, digest_s);
        size_t idx = maid_hmac_sha2_s(bits64, digest_s);
        ret->hash = maid_sha2(&(((u8*)ret->prf)[idx]), bits64, digest_s);

        if (ret->prf && ret->hash)
            ret->output_s = output_s;
        else
            ret = NULL;
    }
    else
        ret = NULL;

    return ret;
}

static size_t
hkdf_size(u8 state_s, u8 digest_s, size_t output_s)
{
    (void)output_s;

    bool bits64 = (state_s == 128);
    return sizeof(struct hkdf) +
           maid_sha2_s(bits64, digest_s) + maid_hmac_sha2_s(bits64, digest_s);
}

static void
hkdf_config(void *ctx, const u8 *info, size_t info_s)
{
    if (ctx)
    {
        struct hkdf *p = ctx;
        p->info   = info;
        p->info_s = info_s;
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
            maid_hash_update(p->hash, salt, salt_s);
            maid_hash_digest(p->hash, key);
        }
        else
            maid_mem_copy(key, salt, salt_s);
        maid_mac_config(p->prf, key);
        maid_mac_update(p->prf, data, data_s);
        maid_mac_digest(p->prf, key);

        /* OKM = HKDF_Expand(PRK, info, output_s) */
        size_t l = p->output_s;
        for (u8 i = 1; l; i++)
        {
            maid_mac_config(p->prf, key);
            if (i != 1)
                maid_mac_update(p->prf, &(output[p->digest_s * (i - 2)]),
                                p->digest_s);
            maid_mac_update(p->prf, p->info, p->info_s);

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
                maid_mem_copy(&(output[p->digest_s * (i - 1)]), hash, l);

                maid_mem_clear(hash, sizeof(hash));
                l = 0;
            }
        }
    }
}

static const struct maid_kdf_def hkdf_sha2_def =
{
    .init   = hkdf_init,
    .size   = hkdf_size,
    .config = hkdf_config,
    .hash   = hkdf_hash,
};

extern maid_kdf *
maid_hkdf_sha2(void *buffer, bool bits64, u8 digest_s, size_t output_s)
{
    return maid_kdf_init(buffer, maid_hkdf_sha2_s(bits64, digest_s, output_s),
                         &hkdf_sha2_def, (bits64) ? 128 : 64,
                         digest_s, output_s);
}

extern size_t
maid_hkdf_sha2_s(bool bits64, u8 digest_s, size_t output_s)
{
    size_t ret = 0;

    if (digest_s == 28 || digest_s == 32 ||
        (bits64 && digest_s == 48) || (bits64 && digest_s == 64))
        ret = maid_kdf_size(&hkdf_sha2_def, (bits64) ? 128 : 64,
                            digest_s, output_s);

    return ret;
}
