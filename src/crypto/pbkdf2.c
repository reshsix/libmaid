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

#include <maid/pass.h>

/* Maid PASS definition */

enum
{
    SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256
};

struct pbkdf2
{
    struct maid_pbkdf2_params prm;
    maid_mac  *prf;
    maid_hash *hash;
    size_t key_s, digest_s;
};

static void *
pbkdf2_del(void *ctx)
{
    if (ctx)
    {
        struct pbkdf2 *p = ctx;
        maid_mac_del(p->prf);
        maid_hash_del(p->hash);

        maid_mem_clear(ctx, sizeof(struct pbkdf2));
    }
    free(ctx);

    return NULL;
}

static void *
pbkdf2_new(u8 version, const void *params)
{
    struct pbkdf2 *ret = calloc(1, sizeof(struct pbkdf2));

    if (ret)
    {
        const struct maid_mac_def  *mdef = NULL;
        const struct maid_hash_def *hdef = NULL;

        switch (version)
        {
            case SHA1:
                mdef = &maid_hmac_sha1;
                hdef = &maid_sha1;
                ret->key_s    = 64;
                ret->digest_s = 20;
                break;
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

        u8 empty[128] = {0};
        ret->prf  = maid_mac_new(*mdef, empty);
        ret->hash = maid_hash_new(*hdef);
        if (ret->prf && ret->hash)
            memcpy(&(ret->prm), params, sizeof(struct maid_pbkdf2_params));
        else
            ret = pbkdf2_del(ret);
    }

    return ret;
}

static void
pbkdf2_renew(void *ctx, const void *params)
{
    if (ctx && params)
    {
        struct pbkdf2 *p = ctx;
        memcpy(&(p->prm), params, sizeof(struct maid_pbkdf2_params));
    }
}

static void
pbkdf2_hash(void *ctx, const char *pwd,
            const u8 *salt, size_t salt_s, u8 *output)
{
    if (ctx && pwd && salt && output)
    {
        struct pbkdf2 *p = ctx;
        maid_mem_clear(output, p->prm.output_s);

        u8 key[p->key_s];
        maid_mem_clear(key, sizeof(key));

        size_t len = strlen(pwd);
        if (len <= sizeof(key))
            memcpy(key, pwd, len);
        else
        {
            maid_hash_renew(p->hash);
            maid_hash_update(p->hash, (u8*)pwd, len);
            maid_hash_digest(p->hash, key);
        }

        maid_mac_renew(p->prf, key);
        maid_mem_clear(key, sizeof(key));

        size_t out_s = p->prm.output_s;
        size_t digest_s = p->digest_s;

        u8 buffer[digest_s];
        for (u32 b = 1; out_s; b++)
        {
            if (out_s < digest_s)
                digest_s = out_s;

            u8 b32[4] = {0};
            maid_mem_write(b32, 0, sizeof(b32), true, b);

            maid_mac_renew(p->prf, NULL);
            maid_mac_update(p->prf, salt, salt_s);
            maid_mac_update(p->prf, b32, sizeof(b32));
            maid_mac_digest(p->prf, buffer);
            for (size_t i = 0; i < digest_s; i++)
                output[i] ^= buffer[i];

            for (u32 i = 1; i < p->prm.iterations; i++)
            {
                maid_mac_renew(p->prf, NULL);
                maid_mac_update(p->prf, buffer, sizeof(buffer));
                maid_mac_digest(p->prf, buffer);
                for (size_t j = 0; j < digest_s; j++)
                    output[j] ^= buffer[j];
            }

            output = &(output[digest_s]);
            out_s -= digest_s;
        }
        maid_mem_clear(buffer, sizeof(buffer));
    }
}

const struct maid_pass_def maid_pbkdf2_sha1 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA1
};

const struct maid_pass_def maid_pbkdf2_sha224 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA224
};

const struct maid_pass_def maid_pbkdf2_sha256 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA256
};

const struct maid_pass_def maid_pbkdf2_sha384 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA384
};

const struct maid_pass_def maid_pbkdf2_sha512 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA512
};

const struct maid_pass_def maid_pbkdf2_sha512_224 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA512_224
};

const struct maid_pass_def maid_pbkdf2_sha512_256 =
{
    .new     = pbkdf2_new,
    .del     = pbkdf2_del,
    .renew   = pbkdf2_renew,
    .hash    = pbkdf2_hash,
    .version = SHA512_256
};
