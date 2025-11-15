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

#ifndef MAID_MEM_H
#define MAID_MEM_H

#include <stdint.h>
#include <stdbool.h>

uint64_t maid_mem_read(const void *addr, size_t index,
                       size_t length, bool big);
void maid_mem_write(void *addr, size_t index,
                    size_t length, bool big, uint64_t data);
void maid_mem_clear(void *addr, size_t length);
bool maid_mem_cmp(const void *addr, const void *addr2, size_t length);

enum maid_mem
{
    MAID_BASE16L,
    MAID_BASE16U,
    MAID_BASE32,
    MAID_BASE32HEX,
    MAID_BASE64,
    MAID_BASE64URL
};
size_t maid_mem_import(enum maid_mem type, void *addr, size_t limit,
                       const char *input, size_t length);
size_t maid_mem_export(enum maid_mem type, const void *addr, size_t length,
                       char *output, size_t limit);

#endif
