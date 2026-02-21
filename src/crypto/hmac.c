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

#include <maid/crypto/sha2.h>
#include <maid/crypto/hmac_sha2.h>

/* Maid MAC definition */

struct hmac
{
    maid_hash *hash;
    size_t hash_s;

    size_t bytes;
    u8 key[128], prefix[128], buffer[128];
};

static void
hmac_setup(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct hmac *h = ctx;
        if (key)
            memcpy(h->key, key, h->bytes);

        maid_hash_digest(h->hash, h->buffer);

        memcpy(h->prefix, h->key, h->bytes);
        for (size_t i = 0; i < h->bytes; i++)
            h->prefix[i] ^= 0x5c;

        memcpy(h->buffer, h->key, h->bytes);
        for (size_t i = 0; i < h->bytes; i++)
            h->buffer[i] ^= 0x36;

        maid_hash_update(h->hash, h->buffer, h->bytes);
    }
}

static void *
hmac_init(void *buffer, u8 key_s, u8 state_s, u8 digest_s)
{
    struct hmac *ret = buffer;

    (void)key_s;
    ret->hash_s = digest_s;
    ret->bytes  = state_s;

    ret->hash = maid_sha2(&(ret[1]), (state_s == 128), digest_s);
    if (!(ret->hash))
        ret = NULL;

    return ret;
}

static size_t
hmac_size(u8 key_s, u8 state_s, u8 digest_s)
{
    (void)key_s;
    return sizeof(struct hmac) + maid_sha2_s((state_s == 128), digest_s);
}

static void
hmac_config(void *ctx, const u8 *key)
{
    if (ctx && key)
        hmac_setup(ctx, key);
}

static void
hmac_update(void *ctx, const u8 *block, size_t size)
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

        maid_hash_update(h->hash, h->prefix, h->bytes);
        maid_hash_update(h->hash, h->buffer, h->hash_s);
        maid_hash_digest(h->hash, output);

        hmac_setup(ctx, NULL);
    }
}

static const struct maid_mac_def hmac_sha2 =
{
    .init   = hmac_init,
    .size   = hmac_size,
    .config = hmac_config,
    .update = hmac_update,
    .digest = hmac_digest,
};

extern maid_mac *
maid_hmac_sha2(void *buffer, bool bits64, u8 digest_s)
{
    maid_mac *ret = NULL;

    if (digest_s == 28 || digest_s == 32 ||
        (bits64 && digest_s == 48) || (bits64 && digest_s == 64))
        ret = maid_mac_init(buffer, maid_hmac_sha2_s(bits64, digest_s),
                            &hmac_sha2, 0, (bits64) ? 128 : 64, digest_s);

    return ret;
}

extern size_t
maid_hmac_sha2_s(bool bits64, u8 digest_s)
{
    size_t ret = 0;

    if (digest_s == 28 || digest_s == 32 ||
        (bits64 && digest_s == 48) || (bits64 && digest_s == 64))
        ret = maid_mac_size(&hmac_sha2, 0, (bits64) ? 128 : 64, digest_s);

    return ret;
}
