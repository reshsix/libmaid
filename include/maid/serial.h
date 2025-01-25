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

#ifndef MAID_SERIAL_H
#define MAID_SERIAL_H

#include <maid/types.h>

struct maid_pem
{
    enum
    {
        MAID_PEM_UNKNOWN,
        MAID_PEM_PUBLIC_RSA,
        MAID_PEM_PRIVATE_RSA,
        MAID_PEM_PUBLIC,
        MAID_PEM_PRIVATE
    } type;
    u8 *data;
    size_t size;
};

struct maid_pem *maid_pem_import(const char *input, const char **endptr);
char *maid_pem_export(struct maid_pem *p);
struct maid_pem *maid_pem_free(struct maid_pem *p);

enum maid_serial
{
    MAID_SERIAL_UNKNOWN,
    MAID_SERIAL_RSA_PUBLIC,
    MAID_SERIAL_RSA_PRIVATE,
    MAID_SERIAL_PKCS8_RSA_PUBLIC,
    MAID_SERIAL_PKCS8_RSA_PRIVATE
};

enum maid_serial maid_serial_import(struct maid_pem *p, size_t *bits,
                                    maid_mp_word **output);
struct maid_pem *maid_serial_export(enum maid_serial s, size_t bits,
                                    maid_mp_word **input);

#endif
