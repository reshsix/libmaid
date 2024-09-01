<!---
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
--->

# Block ciphers

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/block.h>

int main(void)
{
    u8 key[32] = {0};
    u8 iv [16] = {0};

    maid_block *bl = maid_block_new(maid_aes_256, key, iv);

    u8 data[64] = {0};
    if (bl)
        maid_block_ctr(bl, data, sizeof(data));

    maid_block_del(bl);

    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x", data[i]);
    printf("\n");

    return EXIT_SUCCESS;
}
```

```sh
cc example.c -lmaid
```
