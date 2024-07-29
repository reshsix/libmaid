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

static void
gf128_mul(const u8 *a, const u8 *b, u8 *out)
{
    memset(out, '\0', 16);

    u8 tmp[16] = {0};
    memcpy(tmp, b, sizeof(tmp));

    volatile u8 value = 0x0;
    for (u8 i = 0; i < 128; i++)
    {
        u8 x = i / 8, y = i % 8;
        bool ai = (a[x] >> (7 - y)) & 0x1;
        for (u8 j = 0; j < 16; j++)
        {
            value = (ai) ? tmp[j] : 0x0;
            out[j] ^= value;
        }

        bool v0 = tmp[15] & 0x1;

        volatile u8 carry = 0;
        for (u8 j = 0; j < 16; j++)
        {
            value = tmp[j];
            tmp[j] >>= 1;
            tmp[j] |= (carry) ? 0x80 : 0x0;
            carry = value & 0x1;
        }
        carry = 0;

        value = (v0) ? 0xE1 : 0x0;
        tmp[0] ^= value;
    }
    value = 0x0;

    maid_mem_clear(tmp, 16);
}

extern void
maid_gmac_ghash(const u8 *h, const u8 *nonce,
                const struct maid_cb_read *ct,
                const struct maid_cb_read *ad, u8 *tag)
{
    u8 tmp[16] = {0};

    u64 ad_s = 0, ct_s = 0;
    u8 step = 0, block[16] = {0};
    while (true)
    {
        u8 last = 0;
        switch (step)
        {
            case 0:
                last = ad->f(ad->ctx, block, 16);
                if (last)
                    ad_s += last;
                else
                {
                    step++;
                    continue;
                }
                break;
            case 1:
                last = ct->f(ct->ctx, block, 16);
                if (last)
                    ct_s += last;
                else
                {
                    step++;
                    continue;
                }
                break;
            case 2:
                last = 16;
                memcpy(block, &ad_s, sizeof(u64));
                memcpy(&(block[8]), &ct_s, sizeof(u64));
                step++;
            default:
                break;
        }
        if (last == 0)
            break;

        if (last < 16)
            memset(&(block[last]), '\0', 16 - last);

        for (u8 i = 0; i < 16; i++)
            block[i] ^= tmp[i];
        gf128_mul(block, h, tmp);
    }
    maid_mem_clear(block, 16);

    for (u8 i = 0; i < 16; i++)
        tmp[i] ^= nonce[i];
    memcpy(tag, tmp, 16);

    maid_mem_clear(tmp, 16);
}
