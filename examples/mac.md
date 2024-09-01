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

# Message Authentication Codes

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mac.h>

int main(void)
{
    u8 key[32] = {0};
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = i;

    maid_mac *m = maid_mac_new(maid_poly1305, key);

    u8 data[64] = {0};
    u8  tag[16] = {0};
    if (m)
    {
        maid_mac_update(m, data, sizeof(data));
        maid_mac_digest(m, tag);
    }

    maid_mac_del(m);

    for (size_t i = 0; i < sizeof(tag); i++)
        printf("%02x", tag[i]);
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
