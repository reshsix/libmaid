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
#include <maid/rng.h>

struct maid_rng
{
    struct maid_rng_def def;
    void *ctx;

    u8 *buffer;
    size_t buffer_c;
    bool initialized;
};

extern struct maid_rng *
maid_rng_del(struct maid_rng *g)
{
    if (g)
    {
        g->def.del(g->ctx);

        if (g->buffer)
            maid_mem_clear(g->buffer, g->def.state_s);
        free(g->buffer);
    }
    free(g);

    return NULL;
}

extern struct maid_rng *
maid_rng_new(struct maid_rng_def def, const u8 *entropy)
{
    struct maid_rng *ret = calloc(1, sizeof(struct maid_rng));

    if (ret)
    {
        memcpy(&(ret->def), &def, sizeof(struct maid_rng_def));
        ret->ctx = def.new(def.version, entropy);

        ret->buffer = calloc(1, def.state_s);
        if (!(ret->ctx && ret->buffer))
            ret = maid_rng_del(ret);
    }

    return ret;
}

extern void
maid_rng_renew(struct maid_rng *g, const u8 *entropy)
{
    if (g)
    {
        if (entropy)
            g->def.renew(g->ctx, entropy);

        g->buffer_c = 0;
        g->initialized = false;
        maid_mem_clear(g->buffer, g->def.state_s);
    }
}

extern void
maid_rng_generate(struct maid_rng *g, u8 *buffer, size_t size)
{
    if (g && buffer)
    {
        while (size)
        {
            size_t aval = (g->initialized) ? g->def.state_s -
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

                g->def.generate(g->ctx, g->buffer);
                g->buffer_c = 0;
                g->initialized = true;
            }
        }
    }
}
