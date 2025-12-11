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

#include <internal/mac.h>
#include <internal/types.h>

/* Maid MAC definition */

struct hmac
{
    maid_hash *hash;
    size_t hash_s;

    size_t bytes;
    u8 key[128], prefix[128], buffer[128];
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
        maid_mem_clear(ctx, sizeof(struct hmac));
    }
    free(ctx);

    return NULL;
}

static void *
hmac_new(const u8 *key, u8 key_s, u8 state_s, u8 digest_s)
{
    struct hmac *ret = calloc(1, sizeof(struct hmac));

    (void)key_s;
    if (ret)
    {
        ret->hash   = maid_sha2((state_s == 128), digest_s);
        ret->hash_s = digest_s;
        ret->bytes  = state_s;

        if (ret->hash)
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

static const struct maid_mac_def hmac_sha2 =
{
    .new    = hmac_new,
    .del    = hmac_del,
    .renew  = hmac_renew,
    .update = hmac_update,
    .digest = hmac_digest,
};

extern maid_mac *
maid_hmac_sha2(bool bits64, const u8 *key, u8 digest_s)
{
    maid_mac *ret = NULL;

    if (digest_s == 28 || digest_s == 32 ||
        (bits64 && digest_s == 48) || (bits64 && digest_s == 64))
        ret = maid_mac_new(&hmac_sha2, key, 0, (bits64) ? 128 : 64, digest_s);

    return ret;
}
