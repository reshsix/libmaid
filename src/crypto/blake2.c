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
#include <internal/hash.h>
#include <internal/types.h>

static u32
rr32(u32 a, u8 n)
{
    return (a >> n) | (a << (32 - n));
}

static u64
rr64(u64 a, u8 n)
{
    return (a >> n) | (a << (64 - n));
}

/* BLAKE2 implementation */

static void
g32(u32 *v, u8 a, u8 b, u8 c, u8 d, u32 x, u32 y)
{
    v[a] += v[b] + x;
    v[d] = rr32(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = rr32(v[b] ^ v[c], 12);
    v[a] += v[b] + y;
    v[d] = rr32(v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b] = rr32(v[b] ^ v[c], 7);
}

static void
g64(u64 *v, u8 a, u8 b, u8 c, u8 d, u64 x, u64 y)
{
    v[a] += v[b] + x;
    v[d] = rr64(v[d] ^ v[a], 32);
    v[c] += v[d];
    v[b] = rr64(v[b] ^ v[c], 24);
    v[a] += v[b] + y;
    v[d] = rr64(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = rr64(v[b] ^ v[c], 63);
}

const uint8_t sigma[12][16] = {
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
   { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
   { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
   { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
   { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
   { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
   { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
   { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
   { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

const u32 iv32[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

const u64 iv64[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                     0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                     0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                     0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

static void
f32(u32 *h, const u32 *m, u64 t, bool f)
{
    u32 v[16] = {0};
    for (u8 i = 0; i < 8; i++)
        v[i] = h[i];
    for (u8 i = 8; i < 16; i++)
        v[i] = iv32[i - 8];

    v[12] ^= (t >> 0);
    v[13] ^= (t >> 32);

    if (f)
        v[14] ^= 0xFFFFFFFF;

    u8 s[16] = {0};
    for (u8 i = 0; i < 10; i++)
    {
        for (u8 j = 0; j < 16; j++)
            s[j] = sigma[i][j];

        g32(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g32(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g32(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g32(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

        g32(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g32(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g32(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g32(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    maid_mem_clear(s, sizeof(s));

    for (u8 i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i + 8];

    maid_mem_clear(v, sizeof(v));
}

static void
f64(u64 *h, const u64 *m, u64 th, u64 tl, bool f)
{
    u64 v[16] = {0};
    for (u8 i = 0; i < 8; i++)
        v[i] = h[i];
    for (u8 i = 8; i < 16; i++)
        v[i] = iv64[i - 8];

    v[12] ^= tl;
    v[13] ^= th;

    if (f)
        v[14] ^= 0xFFFFFFFFFFFFFFFF;

    u8 s[16] = {0};
    for (u8 i = 0; i < 12; i++)
    {
        for (u8 j = 0; j < 16; j++)
            s[j] = sigma[i % 10][j];

        g64(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        g64(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        g64(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        g64(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

        g64(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        g64(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g64(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        g64(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    maid_mem_clear(s, sizeof(s));

    for (u8 i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i + 8];

    maid_mem_clear(v, sizeof(v));
}

enum
{
    BLAKE2S  = 0,
    BLAKE2B  = BLAKE2S  + 64,
    BLAKE2SK = BLAKE2B  + 64,
    BLAKE2BK = BLAKE2SK + 64
};

static void
blake2_init(u8 version, void *h, u8 *nn, bool *bits64, bool *keyed)
{
    size_t kk = 0;
    bool v64 = false;
    *nn = version + 1;
    if (version < BLAKE2B)
        *nn -= BLAKE2S;
    else if (version < BLAKE2SK)
    {
        v64 = true;
        *nn -= BLAKE2B;
    }
    else if (version < BLAKE2BK)
    {
        kk = 32;
        *nn -= BLAKE2SK;
    }
    else
    {
        kk = 64;
        v64 = true;
        *nn -= BLAKE2BK;
    }

    if (v64)
    {
        memcpy(h, iv64, sizeof(iv64));
        ((u64*)h)[0] ^= (0x01010000 | (kk << 8) | *nn);
    }
    else
    {
        memcpy(h, iv32, sizeof(iv32));
        ((u32*)h)[0] ^= (0x01010000 | (kk << 8) | *nn);
    }

    *bits64 = v64;
    *keyed  = (kk != 0);
}

static void
blake2_rounds(void *h, void *d, size_t length, bool bits64, bool last)
{
    if (bits64)
    {
        /* BLAKE2b supports 2^128 bytes of input,
         * but 2^64 is way more than enough */
        f64(h, d, 0, length, last);
    }
    else
        f32(h, d, length, last);
}

static void
blake2_output(void *h, bool bits64, u8 length, u8 *tag)
{
    if (!bits64)
    {
        u32 *h32 = h;
        for (u8 i = 0; i < length; i++)
            maid_mem_write(tag, i, sizeof(u32), false, h32[i]);
    }
    else
    {
        u64 *h64 = h;
        for (u8 i = 0; i < length - 1; i++)
            maid_mem_write(tag, i, sizeof(u64), false, h64[i]);

        maid_mem_write(tag, (length - 1) * 2,  sizeof(u32), false,
                       h64[length - 1] >> 32);
    }
}

/* Maid hash definition */

struct blake2
{
    u8 version;
    bool bits64, keyed;
    u8 nn;

    u64 h[8];
    u8 buf[128];
    size_t length;
    bool first, last;
};

static void *
blake2_del(void *ctx)
{
    if (ctx)
        maid_mem_clear(ctx, sizeof(struct blake2));
    free(ctx);
    return NULL;
}

static void *
blake2_new(u8 version)
{
    struct blake2 *b2 = calloc(1, sizeof(struct blake2));

    if (b2)
    {
        b2->version = version;
        b2->first = true;
        blake2_init(b2->version, &(b2->h), &(b2->nn),
                    &(b2->bits64), &(b2->keyed));
    }

    return b2;
}

static void
blake2_renew(void *ctx)
{
    if (ctx)
    {
        struct blake2 *b2 = ctx;
        blake2_init(b2->version, &(b2->h), &(b2->nn),
                    &(b2->bits64), &(b2->keyed));
        b2->length = 0;
        b2->first = true;
        b2->last = false;
        maid_mem_clear(b2->buf, sizeof(b2->buf));
    }
}

static void
blake2_update(void *ctx, u8 *buffer, size_t size)
{
    if (ctx)
    {
        struct blake2 *b2 = ctx;

        if (!(b2->first))
            blake2_rounds(b2->h, b2->buf, b2->length, b2->bits64, false);

        size_t limit = (b2->bits64) ? 128 : 64;
        if (size >= limit)
        {
            b2->length += size;
            memcpy(b2->buf, buffer, size);
        }
        else
        {
            b2->last = true;
            b2->length += size;
            blake2_rounds(b2->h, buffer, b2->length, b2->bits64, true);
        }
        b2->first = false;
    }
}

static void
blake2_digest(void *ctx, u8 *output)
{
    if (ctx)
    {
        struct blake2 *b2 = ctx;

        if (!(b2->last))
        {
            b2->last = true;
            blake2_rounds(b2->h, b2->buf, b2->length, b2->bits64, true);
        }

        blake2_output(b2->h, b2->bits64, b2->nn, output);
    }
}

extern maid_hash *
maid_blake2s(u8 digest_s)
{
    const struct maid_hash_def def =
    {
        .new = (digest_s && digest_s <= 64) ? blake2_new : NULL,
        .del = blake2_del,
        .renew = blake2_renew,
        .update = blake2_update,
        .digest = blake2_digest,
        .state_s = 64,
        .digest_s = digest_s,
        .version = BLAKE2S + digest_s - 1
    };

    return maid_hash_new(&def);
}

extern maid_hash *
maid_blake2b(u8 digest_s)
{
    const struct maid_hash_def def =
    {
        .new = (digest_s && digest_s <= 64) ? blake2_new : NULL,
        .del = blake2_del,
        .renew = blake2_renew,
        .update = blake2_update,
        .digest = blake2_digest,
        .state_s = 128,
        .digest_s = digest_s,
        .version = BLAKE2B + digest_s - 1
    };

    return maid_hash_new(&def);
}

/* Maid MAC definition */

struct blake2k
{
    u8 version;
    struct blake2 *b2;
};

static void
blake2k_init(void *ctx, const u8 *key)
{
    if (ctx)
    {
        struct blake2k *b2k = ctx;

        size_t kk = (b2k->version >= BLAKE2BK) ? 64 : 32;
        if (b2k->b2)
            blake2_renew(b2k->b2);
        else
            b2k->b2 = blake2_new(b2k->version);

        u8 buf[128] = {0};
        memcpy(buf, key, kk);
        blake2_update(b2k->b2, buf, kk * 2);
        maid_mem_clear(buf, sizeof(buf));
    }
}

static void *
blake2k_del(void *ctx)
{
    if (ctx)
    {
        struct blake2k *b2k = ctx;
        blake2_del(b2k->b2);
    }

    return NULL;
}

static void *
blake2k_new(u8 version, const u8 *key)
{
    struct blake2k *ret = calloc(1, sizeof(struct blake2k));

    if (ret)
    {
        ret->version = version;
        blake2k_init(ret, key);
        if (!(ret->b2))
        {
            free(ret);
            ret = NULL;
        }
    }

    return ret;
}

static void
blake2k_renew(void *ctx, const u8 *key)
{
    blake2k_init(ctx, key);
}

static void
blake2k_update(void *ctx, u8 *block, size_t size)
{
    if (ctx && block)
    {
        struct blake2k *b2k = ctx;
        blake2_update(b2k->b2, block, size);
    }
}

static void
blake2k_digest(void *ctx, u8 *output)
{
    if (ctx && output)
    {
        struct blake2k *b2k = ctx;
        blake2_digest(b2k->b2, output);
    }
}

extern maid_mac *
maid_blake2s_k(const u8 *key, u8 digest_s)
{
    const struct maid_mac_def def =
    {
        .new = (digest_s && digest_s <= 64) ? blake2k_new : NULL,
        .del = blake2k_del,
        .renew = blake2k_renew,
        .update = blake2k_update,
        .digest = blake2k_digest,
        .state_s = 64,
        .digest_s = digest_s,
        .version = BLAKE2SK + digest_s - 1
    };

    return maid_mac_new(&def, key);
}

extern maid_mac *
maid_blake2b_k(const u8 *key, u8 digest_s)
{
    const struct maid_mac_def def =
    {
        .new = (digest_s && digest_s <= 64) ? blake2k_new : NULL,
        .del = blake2k_del,
        .renew = blake2k_renew,
        .update = blake2k_update,
        .digest = blake2k_digest,
        .state_s = 128,
        .digest_s = digest_s,
        .version = BLAKE2BK + digest_s - 1
    };

    return maid_mac_new(&def, key);
}
