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

# Hash Functions

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <maid/hash.h>

int main(void)
{
    maid_hash *h = maid_hash_new(maid_sha256);

    char *data = "abc";
    u8 output[32] = {0};
    if (h)
    {
        maid_hash_update(h, (u8*)data, strlen(data));
        maid_hash_digest(h, output);
    }

    maid_hash_del(h);

    for (size_t i = 0; i < sizeof(output); i++)
        printf("%02x", output[i]);
    printf("\n");

    return EXIT_SUCCESS;
}
```

Without installation:
```sh
cc -static -Iinclude example.c -Lbuild -lmaid
```

With installation:
```sh
cc example.c -lmaid
```
