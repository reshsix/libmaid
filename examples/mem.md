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

# Memory utils

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>

int main(void)
{
    u8 memory[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    u32 integer = maid_mem_read(memory, 0, sizeof(u32), true);
    maid_mem_write(memory, 1, sizeof(u32), false, integer ^ 0xed0cee0e);

    for (size_t i = 0; i < sizeof(memory); i++)
        printf("%02x", memory[i]);
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
