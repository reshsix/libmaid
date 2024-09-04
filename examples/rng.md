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

# Random Number Generators

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/rng.h>

int main(void)
{
    u8 entropy[32] = {0xc2, 0xae, 0x5a, 0x05, 0x39, 0x3a, 0x57, 0xf6,
                      0x2b, 0xa3, 0xc2, 0xec, 0x80, 0x4a, 0x23, 0xda,
                      0x37, 0x81, 0xa6, 0xa0, 0x94, 0x4a, 0xe7, 0xbf,
                      0xd4, 0xe5, 0xda, 0xc9, 0x29, 0x14, 0x83, 0x65};

    maid_rng *g = maid_rng_new(maid_ctr_drbg_aes_128, entropy);

    u8 data[64] = {0};
    if (g)
        maid_rng_generate(g, data, sizeof(data));

    maid_rng_del(g);

    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x", data[i]);
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
