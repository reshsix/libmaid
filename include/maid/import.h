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

#ifndef MAID_IMPORT_H
#define MAID_IMPORT_H

#include <maid/types.h>

struct maid_import
{
    enum
    {
        MAID_IMPORT_UNKNOWN,
        MAID_IMPORT_PUBLIC_RSA,
        MAID_IMPORT_PRIVATE_RSA,
        MAID_IMPORT_PUBLIC,
        MAID_IMPORT_PRIVATE
    } type;
    u8 *data;
    size_t size;
};

struct maid_import *maid_import_pem(const char *input, const char **endptr);
struct maid_import *maid_import_free(struct maid_import *im);

#include <maid/pub.h>
maid_pub *maid_import_pub(struct maid_import *im);

#endif
