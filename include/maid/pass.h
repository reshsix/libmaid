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

#ifndef MAID_PASS_H
#define MAID_PASS_H

#include <maid/types.h>

/* Internal interface */

struct maid_pass_def
{
    void * (*new)(u8, const void *);
    void * (*del)(void *);
    void (*renew)(void *, const void *);
    void (*hash)(void *, const char *,
                 const u8 *, size_t, u8 *);
    u8 version;
};

/* External interface */

typedef struct maid_pass maid_pass;
maid_pass *maid_pass_new(struct maid_pass_def def, const void *params);
maid_pass *maid_pass_del(maid_pass *p);
void maid_pass_renew(maid_pass *p, const void *params);
void maid_pass_hash(struct maid_pass *p, const char *pwd,
                    const u8 *salt, size_t salt_s, u8 *output);

/* External algorithms */

#include <maid/mac.h>

struct maid_pbkdf2_params
{
    u32 iterations;
    u32 output_s;
};

extern const struct maid_pass_def maid_pbkdf2_sha1;
extern const struct maid_pass_def maid_pbkdf2_sha224;
extern const struct maid_pass_def maid_pbkdf2_sha256;
extern const struct maid_pass_def maid_pbkdf2_sha384;
extern const struct maid_pass_def maid_pbkdf2_sha512;
extern const struct maid_pass_def maid_pbkdf2_sha512_224;
extern const struct maid_pass_def maid_pbkdf2_sha512_256;

#endif
