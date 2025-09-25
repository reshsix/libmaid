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

#include <maid/mem.h>
#include <maid/hash.h>

#include <maid/mac.h>

/* Maid MAC definition */

enum
{
    HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512,
    HMAC_SHA512_224, HMAC_SHA512_256
};

struct hmac
{
    maid_hash *hash;
    size_t hash_s;

    size_t bytes;
    u8 *key, *prefix, *buffer;
};

static void
hmac_init(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct hmac *h = ctx;
        if (key)
            memcpy(h->key, key, h->bytes);

        memcpy(h->prefix, h->key, h->bytes);
        for (size_t i = 0; i < h->bytes; i++)
            h->prefix[i] ^= 0x5c;

        maid_hash_renew(h->hash);

        memcpy(h->buffer, h->key, h->bytes);
        for (size_t i = 0; i < h->bytes; i++)
            h->buffer[i] ^= 0x36;
        maid_hash_update(h->hash, h->buffer, h->bytes);
    }
}

static void *
hmac_del(void *ctx)
{
    if (ctx)
    {
        struct hmac *h = ctx;

        maid_hash_del(h->hash);

        maid_mem_clear(h->key,    h->bytes);
        maid_mem_clear(h->prefix, h->bytes);
        maid_mem_clear(h->buffer, h->bytes);

        free(h->key);
        free(h->prefix);
        free(h->buffer);

        maid_mem_clear(ctx, sizeof(struct hmac));
    }
    free(ctx);

    return NULL;
}

static void *
hmac_new(u8 version, const u8 *key)
{
    struct hmac *ret = calloc(1, sizeof(struct hmac));

    if (ret)
    {
        const struct maid_hash_def *def = NULL;
        switch (version)
        {
            case HMAC_SHA224:
                def = &maid_sha224;
                ret->hash_s = 28;
                ret->bytes  = 64;
                break;
            case HMAC_SHA256:
                def = &maid_sha256;
                ret->hash_s = 32;
                ret->bytes  = 64;
                break;
            case HMAC_SHA384:
                def = &maid_sha384;
                ret->hash_s = 48;
                ret->bytes  = 128;
                break;
            case HMAC_SHA512:
                def = &maid_sha512;
                ret->hash_s = 64;
                ret->bytes  = 128;
                break;
            case HMAC_SHA512_224:
                def = &maid_sha512_224;
                ret->hash_s = 28;
                ret->bytes  = 128;
                break;
            case HMAC_SHA512_256:
                def = &maid_sha512_256;
                ret->hash_s = 32;
                ret->bytes  = 128;
                break;
        }

        if (def)
        {
            ret->hash   = maid_hash_new(*def);
            ret->key    = calloc(1, ret->bytes);
            ret->prefix = calloc(1, ret->bytes);
            ret->buffer = calloc(1, ret->bytes);
        }

        if (ret->hash && ret->key && ret->prefix && ret->buffer)
            hmac_init(ret, key);
        else
            ret = hmac_del(ret);
    }

    return ret;
}

static void
hmac_renew(void *ctx, const u8 *key)
{
    hmac_init(ctx, key);
}

static void
hmac_update(void *ctx, u8 *block, size_t size)
{
    if (ctx && block)
    {
        struct hmac *h = ctx;
        maid_hash_update(h->hash, block, size);
    }
}

static void
hmac_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct hmac *h = ctx;

        maid_mem_clear(h->buffer, h->bytes);
        maid_hash_digest(h->hash, h->buffer);
        maid_hash_renew(h->hash);

        maid_hash_update(h->hash, h->prefix, h->bytes);
        maid_hash_update(h->hash, h->buffer, h->hash_s);
        maid_hash_digest(h->hash, output);
    }
}

const struct maid_mac_def maid_hmac_sha224 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 64,
    .digest_s = 28,
    .version = HMAC_SHA224
};

const struct maid_mac_def maid_hmac_sha256 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 64,
    .digest_s = 32,
    .version = HMAC_SHA256
};

const struct maid_mac_def maid_hmac_sha384 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 128,
    .digest_s = 48,
    .version = HMAC_SHA384
};

const struct maid_mac_def maid_hmac_sha512 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 128,
    .digest_s = 64,
    .version = HMAC_SHA512
};

const struct maid_mac_def maid_hmac_sha512_224 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 128,
    .digest_s = 28,
    .version = HMAC_SHA512_224
};

const struct maid_mac_def maid_hmac_sha512_256 =
{
    .new = hmac_new,
    .del = hmac_del,
    .renew = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
    .state_s = 128,
    .digest_s = 32,
    .version = HMAC_SHA512_256
};
