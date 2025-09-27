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
#include <maid/stream.h>
#include <maid/mac.h>

#include <maid/aead.h>

struct maid_aead
{
    u8 step, *buffer;

    const struct maid_aead_def *def;
    maid_stream *s_ctx;
    maid_mac *m_ctx;

    size_t s_ad, s_ct;
};

extern struct maid_aead *
maid_aead_del(struct maid_aead *ae)
{
    if (ae)
    {
        maid_stream_del(ae->s_ctx);
        maid_mac_del(ae->m_ctx);

        maid_mem_clear(ae->buffer, ae->def->m_def->state_s);
        free(ae->buffer);
    }
    free(ae);

    return NULL;
}

extern struct maid_aead *
maid_aead_new(const struct maid_aead_def *def,
              const u8 *restrict key,
              const u8 *restrict nonce)
{
    struct maid_aead *ret = NULL;
    if (key && nonce)
        ret = calloc(1, sizeof(struct maid_aead));

    if (ret)
    {
        ret->def = def;

        bool initialized = false;
        def->init(def->s_def, key, nonce,
                  &(ret->s_ctx), &(ret->m_ctx), false);
        initialized = (ret->s_ctx && ret->m_ctx);

        ret->buffer = calloc(1, def->m_def->state_s);
        if (!(initialized && ret->buffer))
            ret = maid_aead_del(ret);
    }

    return ret;
}

extern void
maid_aead_renew(struct maid_aead *ae, const u8 *restrict key,
                const u8 *restrict nonce)
{
    if (ae)
    {
        ae->def->init(ae->def->s_def, key, nonce,
                      &(ae->s_ctx), &(ae->m_ctx), true);

        ae->step = 0;
        ae->s_ad = 0;
        ae->s_ct = 0;
        maid_mem_clear(ae->buffer, ae->def->m_def->state_s);
    }
}

extern void
maid_aead_update(struct maid_aead *ae, const u8 *buffer, size_t size)
{
    if (ae && buffer && size && ae->step == 0)
    {
        maid_mac_update(ae->m_ctx, buffer, size);
        ae->s_ad += size;
    }
}

extern void
maid_aead_crypt(struct maid_aead *ae, u8 *buffer, size_t size, bool decrypt)
{
    if (ae && buffer && size && ae->step <= 1)
    {
        ae->step = 1;

        /* Additional data padding */
        size_t m_state = ae->def->m_def->state_s;
        if (ae->s_ad % m_state)
            maid_mac_update(ae->m_ctx, ae->buffer,
                            m_state - (ae->s_ad % m_state));

        if (!decrypt)
        {
            ae->def->mode(ae->s_ctx, buffer, size);
            maid_mac_update(ae->m_ctx, buffer, size);
        }
        else
        {
            maid_mac_update(ae->m_ctx, buffer, size);
            ae->def->mode(ae->s_ctx, buffer, size);
        }
        ae->s_ct += size;
    }
}

extern void
maid_aead_digest(struct maid_aead *ae, u8 *output)
{
    if (ae && output)
    {
        ae->step = 2;
        size_t size = ae->def->m_def->state_s;

        /* Ciphertext padding */
        if (ae->s_ct % size)
            maid_mac_update(ae->m_ctx, ae->buffer, size - (ae->s_ct % 16));

        if (ae->def->s_bits)
        {
            ae->s_ad *= 8;
            ae->s_ct *= 8;
        }

        size_t length = size / 2;
        if (!(ae->def->s_big))
        {
            for (u8 i = 0; i < length; i++)
            {
                ae->buffer[i]          = ((u8*)&(ae->s_ad))[i];
                ae->buffer[i + length] = ((u8*)&(ae->s_ct))[i];
            }
        }
        else
        {
            for (u8 i = 0; i < length; i++)
            {
                ae->buffer[length - i - 1] = ((u8*)&(ae->s_ad))[i];
                ae->buffer[size   - i - 1] = ((u8*)&(ae->s_ct))[i];
            }
        }

        maid_mac_update(ae->m_ctx, ae->buffer, size);
        maid_mac_digest(ae->m_ctx, output);
    }
}
