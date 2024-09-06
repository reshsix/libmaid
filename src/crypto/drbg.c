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
#include <maid/block.h>
#include <maid/rng.h>

/* Maid rng definitions */

enum
{
    CTR_DRBG_AES_128, CTR_DRBG_AES_192, CTR_DRBG_AES_256
};

struct ctr_drbg
{
    u8 entropy[48];
    maid_block *bl;
    size_t k_s;
};

static void
ctr_drbg_init(void *ctx, const u8 *entropy)
{
    if (ctx)
    {
        struct ctr_drbg *ctr = ctx;

        u8 key[32] = {0};

        u8 iv[16] = {0};
        iv[15] = 0x1;

        maid_block_renew(ctr->bl, key, iv);

        memcpy(key, entropy, ctr->k_s);
        maid_block_ctr(ctr->bl, key, ctr->k_s);

        memcpy(iv, &(entropy[ctr->k_s]), sizeof(iv));
        maid_block_ctr(ctr->bl, iv, sizeof(iv));

        /* Reseed */
        maid_block_renew(ctr->bl, key, iv);

        /* Discard first 4 + 1 blocks */
        for (u8 i = 0; i < 4 + 1; i++)
            maid_block_ctr(ctr->bl, key, 16);

        /* Reseed */
        memset(key, '\0', ctr->k_s);
        maid_block_ctr(ctr->bl, key, ctr->k_s);
        memset(iv, '\0', sizeof(iv));
        maid_block_ctr(ctr->bl, iv, sizeof(iv));
        maid_block_renew(ctr->bl, key, iv);

        /* Increase counter */
        maid_block_ctr(ctr->bl, key, 16);

        maid_mem_clear(key, sizeof(key));
        maid_mem_clear(iv,  sizeof(iv));

        /* Save entropy for renew */
        memcpy(ctr->entropy, entropy, ctr->k_s + 16);
    }
}

static void *
ctr_drbg_del(void *ctx)
{
    if (ctx)
    {
        struct ctr_drbg *ctr = ctx;
        maid_block_del(ctr->bl);
    }
    free(ctx);

    return NULL;
}

static void *
ctr_drbg_new(u8 version, const u8 *entropy)
{
    struct ctr_drbg *ret = calloc(1, sizeof(struct ctr_drbg));

    if (ret)
    {
        const struct maid_block_def *def = NULL;
        size_t length = 0;
        switch (version)
        {
            case CTR_DRBG_AES_128:
                def = &maid_aes_128;
                length = 16;
                break;

            case CTR_DRBG_AES_192:
                def = &maid_aes_192;
                length = 24;
                break;

            case CTR_DRBG_AES_256:
                def = &maid_aes_256;
                length = 32;
                break;
        }
        ret->k_s = length;

        u8 zeros[32] = {0};
        ret->bl = maid_block_new(*def, zeros, zeros);
        if (ret->bl)
            ctr_drbg_init(ret, entropy);
        else
            ret = ctr_drbg_del(ret);
    }

    return ret;
}

static void
ctr_drbg_renew(void *ctx, const u8 *entropy)
{
    if (ctx)
    {
        struct ctr_drbg *ctr = ctx;
        ctr_drbg_init(ctx, entropy ? entropy : ctr->entropy);
    }
}

static void
ctr_drbg_generate(void *ctx, u8 *buffer)
{
    if (ctx && buffer)
    {
        struct ctr_drbg *ctr = ctx;
        memset(buffer, '\0', 64);
        maid_block_ctr(ctr->bl, buffer, 64);

        u8 next[48] = {0};
        maid_block_ctr(ctr->bl, next, sizeof(next));
        maid_block_renew(ctr->bl, next, &(next[ctr->k_s]));

        /* Increase counter*/
        maid_block_ctr(ctr->bl, next, 16);

        maid_mem_clear(next, sizeof(next));
    }
}

const struct maid_rng_def maid_ctr_drbg_aes_128 =
{
    .new = ctr_drbg_new,
    .del = ctr_drbg_del,
    .renew = ctr_drbg_renew,
    .generate = ctr_drbg_generate,
    .state_s = 64,
    .version = CTR_DRBG_AES_128
};

const struct maid_rng_def maid_ctr_drbg_aes_192 =
{
    .new = ctr_drbg_new,
    .del = ctr_drbg_del,
    .renew = ctr_drbg_renew,
    .generate = ctr_drbg_generate,
    .state_s = 64,
    .version = CTR_DRBG_AES_192
};

const struct maid_rng_def maid_ctr_drbg_aes_256 =
{
    .new = ctr_drbg_new,
    .del = ctr_drbg_del,
    .renew = ctr_drbg_renew,
    .generate = ctr_drbg_generate,
    .state_s = 64,
    .version = CTR_DRBG_AES_256
};
