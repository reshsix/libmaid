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

#include <maid/kdf.h>
#include <maid/mem.h>

#include <internal/kdf.h>
#include <internal/types.h>

struct maid_kdf
{
    const struct maid_kdf_def *def;
    void *ctx;
};

extern struct maid_kdf *
maid_kdf_init(void *buffer, size_t buffer_s,
              const struct maid_kdf_def *def,
              u8 state_s, u8 digest_s, size_t output_s)
{
    struct maid_kdf *ret = buffer;
    maid_mem_clear(buffer, buffer_s);

    ret->def = def;

    ret->ctx = (void *)&(ret[1]);
    if (!(def->init(ret->ctx, state_s, digest_s, output_s)))
        ret = NULL;

    return ret;
}

extern size_t
maid_kdf_size(const struct maid_kdf_def *def,
              u8 state_s, u8 digest_s, size_t output_s)
{
    return sizeof(struct maid_kdf) + def->size(state_s, digest_s, output_s);
}

extern void
maid_kdf_config(struct maid_kdf *m, const u8 *info, size_t info_s)
{
    if (m)
        m->def->config(m->ctx, info, info_s);
}

extern void
maid_kdf_hash(struct maid_kdf *k, const u8 *data, size_t data_s,
              const u8 *salt, size_t salt_s, u8 *output)
{
    if (k)
        k->def->hash(k->ctx, data, data_s, salt, salt_s, output);
}
