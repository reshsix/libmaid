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

# Memory Utils

```c
#include <maid/mem.h>
```

<details>
<summary>u64 maid_mem_read(const void *addr, size_t index,
                           size_t length, bool big); </summary>
Reads integer from memory

### Parameters
| name   | description          |
|--------|----------------------|
| addr   | Memory to be read    |
| index  | Index of the item    |
| length | Length of every item |
| big    | Little/Big endianess |

### Return value
| case   | description   |
|--------|---------------|
| Always | Integer value |

</details>

<details>
<summary>void maid_mem_write(void *addr, size_t index,
                             size_t length, bool big, u64 data); </summary>
Writes integer to memory

### Parameters
| name   | description             |
|--------|-------------------------|
| addr   | Memory to be written on |
| index  | Index of the item       |
| length | Length of every item    |
| big    | Little/Big endianess    |
| data   | Integer value           |

</details>

<details>
<summary>void maid_mem_clear(void *addr, size_t length); </summary>
Clears memory

### Parameters
| name   | description          |
|--------|----------------------|
| addr   | Memory to be cleared |
| length | Length to clear      |

</details>

<details>
<summary>bool maid_mem_cmp(void *addr, void *addr2, size_t length); </summary>
Compares two blocks of memory

### Parameters
| name   | description       |
|--------|-------------------|
| addr   | Memory block 1    |
| addr2  | Memory block 2    |
| length | Length to compare |

### Return value
| case       | description |
|------------|-------------|
| Equal      | True        |
| Not Equal  | False       |

</details>

<details>
<summary>size_t maid_mem_import(void *addr, size_t limit,
                                const char *input, size_t length); </summary>
Imports base64 as memory

### Parameters
| name   | description            |
|--------|------------------------|
| addr   | Memory buffer          |
| limit  | Memory buffer limit    |
| input  | Base64 to be imported  |
| length | Length to be imported  |

### Return value
| case    | description |
|---------|-------------|
| Success | Bytes read  |
| Error   | 0           |

</details>

<details>
<summary>size_t maid_mem_export(const void *addr, size_t length,
                                char *output, size_t limit); </summary>
Exports memory as base64

### Parameters
| name   | description            |
|--------|------------------------|
| addr   | Memory to be exported  |
| length | Length to be exported  |
| output | Base64 buffer          |
| limit  | Base64 buffer limit    |

### Return value
| case   | description   |
|--------|---------------|
| Always | Bytes written |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>

int main(void)
{
    int ret = EXIT_FAILURE;

    char *b64 = "AAECAwQFBgc=";

    u8 memory[8] = {0};
    if (maid_mem_import(memory, sizeof(memory), b64, strlen(b64)))
    {
        u32 integer = maid_mem_read(memory, 0, sizeof(u32), true);
        maid_mem_write(memory, 1, sizeof(u32), false, integer ^ 0xed0cee0e);

        for (size_t i = 0; i < sizeof(memory); i++)
            printf("%02x", memory[i]);
        printf("\n");

        char buf[16] = {0};
        maid_mem_export(memory, sizeof(memory), buf, sizeof(buf));
        printf("%s\n", buf);

        ret = EXIT_SUCCESS;
    }
    else
        fprintf(stderr, "Base64 error\n");

    return ret;
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
