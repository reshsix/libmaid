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

#include <maid/mem.h>
#include <maid/rng.h>

#include <internal/rng.h>
#include <internal/types.h>

struct maid_rng
{
    const struct maid_rng_def *def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool initialized;
};

extern struct maid_rng *
maid_rng_init(void *buffer, size_t buffer_s, const struct maid_rng_def *def)
{
    struct maid_rng *ret = buffer;

    if (ret)
    {
        maid_mem_clear(ret, buffer_s);

        ret->def    = def;
        ret->buffer = (void *)&(ret[1]);

        ret->ctx = &(ret->buffer[def->state_s]);
        if (!def->init(ret->ctx))
            ret = NULL;
    }

    return ret;
}

extern size_t
maid_rng_size(const struct maid_rng_def *def)
{
    return sizeof(struct maid_rng) + def->size() + def->state_s;
}

extern void
maid_rng_config(struct maid_rng *g, const u8 *entropy)
{
    if (g && entropy)
        g->def->config(g->ctx, entropy);
}

extern void
maid_rng_generate(struct maid_rng *g, u8 *buffer, size_t size)
{
    if (g && buffer)
    {
        while (size)
        {
            size_t aval = (g->initialized) ? g->def->state_s -
                                             g->buffer_c: 0;
            if (aval >= size)
            {
                for (u8 i = 0; i < size; i++)
                    buffer[i] = g->buffer[g->buffer_c++];
                size = 0;
            }
            else
            {
                for (u8 i = 0; i < aval; i++)
                    buffer[i] = g->buffer[g->buffer_c++];
                buffer = &(buffer[aval]);
                size -= aval;

                g->def->generate(g->ctx, g->buffer);
                g->buffer_c = 0;
                g->initialized = true;
            }
        }
    }
}
