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

#include <maid/mp.h>
#include <maid/mem.h>

#include <maid/kex.h>

struct dh
{
    size_t bits, words;
    struct maid_dh_group group;
};

extern void *
dh_del(void *dh)
{
    if (dh)
    {
        struct dh *d = dh;
        size_t size = d->words * sizeof(maid_mp_word);

        maid_mem_clear(d->group.generator, size);
        maid_mem_clear(d->group.modulo,    size);

        free(d->group.generator);
        free(d->group.modulo);

        maid_mem_clear(d, sizeof(struct dh));
    }
    free(dh);

    return NULL;
}

extern void *
dh_new(const void *cfg, size_t bits)
{
    struct dh *ret = NULL;

    const struct maid_dh_group *g = cfg;
    if (bits && bits % (sizeof(maid_mp_word) * 8) == 0)
        ret = calloc(1, sizeof(struct dh));

    if (ret)
    {
        ret->bits = bits;
        ret->words = maid_mp_words(ret->bits);
        size_t size = ret->words * sizeof(maid_mp_word);

        ret->group.generator = calloc(1, size);
        ret->group.modulo    = calloc(1, size);

        if (ret->group.generator && ret->group.modulo)
        {
            maid_mp_mov(ret->words, ret->group.generator, g->generator);
            maid_mp_mov(ret->words, ret->group.modulo,    g->modulo);
        }
        else
            ret = dh_del(ret);
    }

    return ret;
}

extern void
dh_renew(void *dh, const void *cfg)
{
    if (dh && cfg)
    {
        struct dh *d = dh;

        const struct maid_dh_group *g = cfg;
        maid_mp_mov(d->words, d->group.generator, g->generator);
        maid_mp_mov(d->words, d->group.modulo,    g->modulo);
    }
}

extern void
dh_gpub(void *dh, const void *private, void *public)
{
    if (dh && private && public)
    {
        struct dh *d = dh;

        maid_mp_word buf[d->words];
        maid_mp_word buf2[d->words];

        maid_mp_mov(d->words, buf, d->group.generator);
        maid_mp_read(d->words, buf2, private, true);

        maid_mp_expmod2(d->words, buf, buf2, d->group.modulo, true);
        maid_mp_write(d->words, buf, public, true);

        maid_mem_clear(buf,  sizeof(buf));
        maid_mem_clear(buf2, sizeof(buf2));
    }
}

extern void
dh_gsec(void *dh, const void *private, const void *public, u8 *buffer)
{
    if (dh && private && public && buffer)
    {
        struct dh *d = dh;

        maid_mp_word buf[d->words];
        maid_mp_word buf2[d->words];

        maid_mp_read(d->words, buf,  public,  true);
        maid_mp_read(d->words, buf2, private, true);

        maid_mp_expmod2(d->words, buf, buf2, d->group.modulo, true);
        maid_mp_write(d->words, buf, buffer, true);

        maid_mem_clear(buf,  sizeof(buf));
        maid_mem_clear(buf2, sizeof(buf2));
    }
}

/* Maid KEX definitions */

const struct maid_kex_def maid_dh =
{
    .new  = dh_new,  .del  = dh_del, .renew = dh_renew,
    .gpub = dh_gpub, .gsec = dh_gsec
};
