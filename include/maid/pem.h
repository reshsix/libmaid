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

#ifndef MAID_PEM_H
#define MAID_PEM_H

#include <maid/types.h>

enum maid_pem_t
{
    MAID_PEM_UNKNOWN,
    MAID_PEM_PUBLIC_RSA,
    MAID_PEM_PRIVATE_RSA,
    MAID_PEM_PUBLIC,
    MAID_PEM_PRIVATE
};

struct maid_pem
{
    enum maid_pem_t type;
    u8 *data;
    size_t size;
};

struct maid_pem *maid_pem_import(const char *input, const char **endptr);
char *maid_pem_export(struct maid_pem *p);
struct maid_pem *maid_pem_free(struct maid_pem *p);

#endif
