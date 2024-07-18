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

#include <string.h>

#include <maid/utils.h>
#include <maid/types.h>

/* Poly1305 implementation */

static void
poly1305(const u8 *key, const struct maid_cb_read *data, u8 *tag)
{
    /* 2^130 - 5 little endian */
    const u32 prime[5] = {0xfffffffb, 0xffffffff,
                          0xffffffff, 0xffffffff, 0x3};

    /* 320 bits, to handle multiplication */
    u32 acc[10] = {0};
    u32 acc2[10] = {0};
    u32 acc3[10] = {0};

    /* R and S initialization */
    u32 r[4] = {0}, s[4] = {0};
    memcpy(r, key, 16);
    memcpy(s, &(key[16]), 16);

    /* R clamping */
    r[0] &= 0x0FFFFFFF;
    r[1] &= 0x0FFFFFFC;
    r[2] &= 0x0FFFFFFC;
    r[3] &= 0x0FFFFFFC;

    u32 block[5] = {0x0};
    while (true)
    {
        memset(block, 0, 20);

        u8 last = data->f(data->ctx, (u8*)block, 16);
        if (last == 0)
            break;
        block[last / 4] |= 0x1 << ((last % 4) * 8);

        /* Adds block to the accumulator */
        maid_mp_add(acc2, acc, block, 10, 10, 5);

        /* Multiplies accumulator by r */
        maid_mp_mul(acc3, acc2, r, 10, 10, 4);

        /* Barret reduction by prime */
        maid_mp_shr(acc, acc3, 130, 10, 10);
        maid_mp_mul(acc2, acc, prime, 10, 10, 5);
        maid_mp_sub(acc, acc3, acc2, 10, 10, 10);
    }

    /* Adds s to the accumulator */
    maid_mp_add(acc2, acc, s, 10, 10, 4);

    /* Exports 128 bits */
    memcpy(tag, acc2, 16);

    /* Cleans intermediary values */
    maid_memset(acc,   '\0', 40);
    maid_memset(acc2,  '\0', 40);
    maid_memset(acc3,  '\0', 40);
    maid_memset(r,     '\0', 16);
    maid_memset(s,     '\0', 16);
    maid_memset(block, '\0', 20);
}

/* External Interface */

struct poly1305_reader
{
    struct maid_cb_read *ad;
    struct maid_cb_read *ct;
    u64 ad_s, ct_s;
    u8 step;
};

static size_t
poly1305_data(void *ctx, u8 *dest, size_t bytes)
{
    /* Bytes is always 16 */
    (void)bytes;

    struct poly1305_reader *r = ctx;

    u8 read = 0;
    bool stop = true;
    do
    {
        /* Concatenates and pads the data accordingly */
        stop = true;
        switch (r->step)
        {
            case 0:
            case 1:
                if (r->step == 0) read = r->ad->f(r->ad->ctx, dest, 16);
                else              read = r->ct->f(r->ct->ctx, dest, 16);
                if (r->step == 0) r->ad_s += read;
                else              r->ct_s += read;

                if (read == 0)
                {
                    r->step++;
                    stop = false;
                }
                else if (read < 16)
                {
                    memset(&(dest[read]), '\0', 16 - read);
                    r->step++;
                }
                read = 16;
                break;

            case 2:
                read = 16;
                memcpy(dest,       &(r->ad_s), 8);
                memcpy(&(dest[8]), &(r->ct_s), 8);
                r->step++;
                break;

            default:
                break;
        }
    } while (!stop);

    return read;
}

extern void
maid_poly1305_mac(const u8 *key, const struct maid_cb_read *ct,
                  const struct maid_cb_read *ad, u8 *tag)
{
    struct poly1305_reader r = {.ad = (struct maid_cb_read *)ad,
                                .ct = (struct maid_cb_read *)ct};
    struct maid_cb_read data = {.f = poly1305_data, .ctx = &r};
    poly1305(key, &data, tag);
}
