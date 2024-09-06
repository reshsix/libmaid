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
| name    | description          |
|---------|----------------------|
| addr    | Memory to be read    |
| index   | Index of the item    |
| length  | Length of every item |
| big     | Little/Big endianess |

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
| name    | description             |
|---------|-------------------------|
| addr    | Memory to be written on |
| index   | Index of the item       |
| length  | Length of every item    |
| big     | Little/Big endianess    |
| data    | Integer value           |

</details>

<details>
<summary>void maid_mem_clear(void *addr, size_t length); </summary>
Clears memory

### Parameters
| name    | description          |
|---------|----------------------|
| addr    | Memory to be cleared |
| length  | Length to clear      |

</details>
