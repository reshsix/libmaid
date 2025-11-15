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

#include <internal/types.h>

static u32
rr32(u32 a, u8 n)
{
    return (a >> n) | (a << (32 - n));
}

static u32
sr32(u32 a, u8 n)
{
    return a >> n;
}

static u64
rr64(u64 a, u8 n)
{
    return (a >> n) | (a << (64 - n));
}

static u64
sr64(u64 a, u8 n)
{
    return a >> n;
}

/* SHA-2 implementation */

enum
{
    SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256
};

static void
sha_init(u8 version, void *h)
{
    switch (version)
    {
        case SHA_224:;
            u32 i224[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                           0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
            memcpy(h, i224, sizeof(i224));
            break;

        case SHA_256:;
            u32 i256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
            memcpy(h, i256, sizeof(i256));
            break;

        case SHA_384:;
            u64 i384[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                           0x9159015a3070dd17, 0x152fecd8f70e5939,
                           0x67332667ffc00b31, 0x8eb44a8768581511,
                           0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
            memcpy(h, i384, sizeof(i384));
            break;

        case SHA_512:;
            u64 i512[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                           0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                           0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                           0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
            memcpy(h, i512, sizeof(i512));
            break;

        case SHA_512_224:;
            u64 i512_224[8] = {0x8c3d37c819544da2, 0x73e1996689dcd4d6,
                               0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
                               0x0f6d2b697bd44da8, 0x77e36f7304c48942,
                               0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1};
            memcpy(h, i512_224, sizeof(i512_224));
            break;

        case SHA_512_256:;
            u64 i512_256[8] = {0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
                               0x2393b86b6f53b151, 0x963877195940eabd,
                               0x96283ee2a88effe3, 0xbe5e1e2553863992,
                               0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2};
            memcpy(h, i512_256, sizeof(i512_256));
            break;
    }
}

static void
sha256_rounds(u32 *h, const u8 *message)
{
    const u32 k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                       0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                       0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                       0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                       0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                       0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                       0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                       0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                       0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    u32 w[64] = {0};
    for (u8 i = 0; i < 16; i++)
        w[i] = maid_mem_read(message, i, sizeof(u32), true);

    for (u8 i = 16; i < 64; i++)
    {
       u32 s0 = rr32(w[i - 15], 7) ^ rr32(w[i - 15], 18) ^ sr32(w[i - 15], 3);
       u32 s1 = rr32(w[i - 2], 17) ^ rr32(w[i - 2],  19) ^ sr32(w[i - 2], 10);
       w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u32 var[] = {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]};

    for (u8 i = 0; i < 64; i++)
    {
        u32 s0 = rr32(var[0], 2) ^ rr32(var[0], 13) ^ rr32(var[0], 22);
        u32 s1 = rr32(var[4], 6) ^ rr32(var[4], 11) ^ rr32(var[4], 25);
        u32 cho = (var[4] & var[5]) ^ ((~var[4]) & var[6]);
        u32 maj = (var[0] & var[1]) ^ (var[0] & var[2]) ^ (var[1] & var[2]);
        u32 tmp1 = var[7] + s1 + cho + k[i] + w[i];
        u32 tmp2 = s0 + maj;

        var[7] = var[6];
        var[6] = var[5];
        var[5] = var[4];
        var[4] = var[3] + tmp1;
        var[3] = var[2];
        var[2] = var[1];
        var[1] = var[0];
        var[0] = tmp1 + tmp2;
    }

    for (u8 i = 0; i < 8; i++)
        h[i] += var[i];
}

static void
sha512_rounds(u64 *h, const u8 *message)
{
    const u64 k[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd,
                       0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                       0x3956c25bf348b538, 0x59f111f1b605d019,
                       0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                       0xd807aa98a3030242, 0x12835b0145706fbe,
                       0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                       0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
                       0x9bdc06a725c71235, 0xc19bf174cf692694,
                       0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                       0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                       0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
                       0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                       0x983e5152ee66dfab, 0xa831c66d2db43210,
                       0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                       0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                       0x06ca6351e003826f, 0x142929670a0e6e70,
                       0x27b70a8546d22ffc, 0x2e1b21385c26c926,
                       0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                       0x650a73548baf63de, 0x766a0abb3c77b2a8,
                       0x81c2c92e47edaee6, 0x92722c851482353b,
                       0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                       0xc24b8b70d0f89791, 0xc76c51a30654be30,
                       0xd192e819d6ef5218, 0xd69906245565a910,
                       0xf40e35855771202a, 0x106aa07032bbd1b8,
                       0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                       0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                       0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                       0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                       0x748f82ee5defb2fc, 0x78a5636f43172f60,
                       0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                       0x90befffa23631e28, 0xa4506cebde82bde9,
                       0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                       0xca273eceea26619c, 0xd186b8c721c0c207,
                       0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                       0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                       0x113f9804bef90dae, 0x1b710b35131c471b,
                       0x28db77f523047d84, 0x32caab7b40c72493,
                       0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                       0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                       0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
    u64 w[80] = {0};
    for (u8 i = 0; i < 16; i++)
        w[i] = maid_mem_read(message, i, sizeof(u64), true);

    for (u8 i = 16; i < 80; i++)
    {
       u64 s0 = rr64(w[i - 15], 1) ^ rr64(w[i - 15],  8) ^ sr64(w[i - 15], 7);
       u64 s1 = rr64(w[i - 2], 19) ^ rr64(w[i - 2],  61) ^ sr64(w[i - 2],  6);
       w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u64 var[] = {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]};

    for (u8 i = 0; i < 80; i++)
    {
        u64 s0 = rr64(var[0], 28) ^ rr64(var[0], 34) ^ rr64(var[0], 39);
        u64 s1 = rr64(var[4], 14) ^ rr64(var[4], 18) ^ rr64(var[4], 41);
        u64 cho = (var[4] & var[5]) ^ ((~var[4]) & var[6]);
        u64 maj = (var[0] & var[1]) ^ (var[0] & var[2]) ^ (var[1] & var[2]);
        u64 tmp1 = var[7] + s1 + cho + k[i] + w[i];
        u64 tmp2 = s0 + maj;

        var[7] = var[6];
        var[6] = var[5];
        var[5] = var[4];
        var[4] = var[3] + tmp1;
        var[3] = var[2];
        var[2] = var[1];
        var[1] = var[0];
        var[0] = tmp1 + tmp2;
    }

    for (u8 i = 0; i < 8; i++)
        h[i] += var[i];
}

static void
sha_rounds(u8 version, void *h, const u8 *message)
{
    switch (version)
    {
        case SHA_224:;
        case SHA_256:;
            sha256_rounds(h, message);
            break;

        case SHA_384:;
        case SHA_512:;
        case SHA_512_224:;
        case SHA_512_256:;
            sha512_rounds(h, message);
            break;
    }
}

static void
sha_output(u8 version, void *h, u8 *tag)
{
    u8 length = 0;
    bool bits64 = false;
    bool trunc = false;

    switch (version)
    {
        case SHA_224:
            length = 7;
            break;

        case SHA_256:
            length = 8;
            break;

        case SHA_384:
            length = 6;
            bits64 = true;
            break;

        case SHA_512:
            length = 8;
            bits64 = true;
            break;

        case SHA_512_224:
            length = 4;
            bits64 = true;
            trunc = true;
            break;

        case SHA_512_256:
            length = 4;
            bits64 = true;
            break;
    }

    if (!bits64)
    {
        u32 *h32 = h;
        for (u8 i = 0; i < length; i++)
            maid_mem_write(tag, i, sizeof(u32), true, h32[i]);
    }
    else if (!trunc)
    {
        u64 *h64 = h;
        for (u8 i = 0; i < length; i++)
            maid_mem_write(tag, i, sizeof(u64), true, h64[i]);
    }
    else
    {
        u64 *h64 = h;
        for (u8 i = 0; i < length - 1; i++)
            maid_mem_write(tag, i, sizeof(u64), true, h64[i]);

        maid_mem_write(tag, (length - 1) * 2,  sizeof(u32), true,
                       h64[length - 1] >> 32);
    }
}

/* Maid hash definition */

struct sha
{
    u8 version;
    bool bits64;
    u64 h[8];

    size_t length;
    bool last;
};

static void *
sha_del(void *ctx)
{
    free(ctx);
    return NULL;
}

static void *
sha_new(u8 version)
{
    struct sha *s2 = calloc(1, sizeof(struct sha));

    if (s2)
    {
        s2->version = version;
        sha_init(s2->version, &(s2->h));

        switch (s2->version)
        {
            case SHA_384:
            case SHA_512:
            case SHA_512_224:
            case SHA_512_256:
                s2->bits64 = true;
                break;
        }
    }

    return s2;
}

static void
sha_renew(void *ctx)
{
    if (ctx)
    {
        struct sha *s2 = ctx;
        sha_init(s2->version, &(s2->h));
        s2->length = 0;
        s2->last = false;
    }
}

static void
sha_update(void *ctx, u8 *buffer, size_t size)
{
    if (ctx)
    {
        struct sha *s2 = ctx;
        s2->length += size;

        u8 limit1 =  (s2->bits64) ? 128 : 64;
        u8 limit2 = ((s2->bits64) ? limit1 - 16 : limit1 - 8) - 1;

        if (size >= limit1)
            sha_rounds(s2->version, &(s2->h), buffer);
        else
        {
            u8 buffer2[128] = {0};
            s2->last = true;
            s2->length *= 8;

            memcpy(buffer2, buffer, size);
            buffer2[size] = 0x80;

            if (size >= limit2)
            {
                sha_rounds(s2->version, &(s2->h), buffer2);
                maid_mem_clear(buffer2, limit1);
            }

            maid_mem_write(buffer2, (limit1 / sizeof(u64)) - 1,
                           sizeof(u64), true, s2->length);

            sha_rounds(s2->version, &(s2->h), buffer2);
        }
    }
}

static void
sha_digest(void *ctx, u8 *output)
{
    if (ctx)
    {
        struct sha *s2 = ctx;

        /* In case the last update was with a 512/1024 bit block */
        if (!(s2->last))
            sha_update(ctx, NULL, 0);

        sha_output(s2->version, &(s2->h), output);
    }
}

const struct maid_hash_def maid_sha224 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 64,
    .digest_s = 28,
    .version = SHA_224
};

const struct maid_hash_def maid_sha256 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 64,
    .digest_s = 32,
    .version = SHA_256
};

const struct maid_hash_def maid_sha384 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 128,
    .digest_s = 48,
    .version = SHA_384
};

const struct maid_hash_def maid_sha512 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 128,
    .digest_s = 64,
    .version = SHA_512
};

const struct maid_hash_def maid_sha512_224 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 128,
    .digest_s = 28,
    .version = SHA_512_224
};

const struct maid_hash_def maid_sha512_256 =
{
    .new = sha_new,
    .del = sha_del,
    .renew = sha_renew,
    .update = sha_update,
    .digest = sha_digest,
    .state_s = 128,
    .digest_s = 32,
    .version = SHA_512_256
};
