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
#include <maid/mp.h>
```

Numbers are represented in a little-endian way
Temporary values are not cleared by the end of functions

<details>
<summary>void maid_mp_debug(size_t words, const char *name,
                            const u32 *a);</summary>
Prints a biginteger

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of u32 words |
| name  | Name to print       |
| a     | Number to print     |

</details>

<details>
<summary>s8 maid_mp_cmp(size_t words, const u32 *a, const u32 *b);</summary>
Compares two bigintegers

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of u32 words |
| a     | Number 1            |
| b     | Number 2 (NULL = 0) |

### Return value
| case  | description |
|-------|-------------|
| a > b | -1          |
| a = b |  0          |
| a < b |  1          |

</details>

<details>
<summary>void maid_mp_mov(size_t words, u32 *a, const u32 *b);</summary>
Sets a biginteger to another

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of u32 words |
| a     | Destination         |
| b     | Source (NULL = 0)   |

</details>

<details>
<summary>void maid_mp_add(size_t words, u32 *a, const u32 *b);</summary>
Adds a biginteger to another

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of u32 words |
| a     | Addend 1 -> Total   |
| b     | Addend 2 (NULL = 0) |

</details>

<details>
<summary>void maid_mp_sub(size_t words, u32 *a, const u32 *b);</summary>
Subtracts a biginteger from another

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of u32 words   |
| a     | Minuend -> Difference |
| b     | Subtrahend (NULL = 0) |

</details>

<details>
<summary>void maid_mp_shl(size_t words, u32 *a, u64 shift);</summary>
Shifts a biginteger left

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of u32 words   |
| a     | Number to be shifted  |
| shift | Amount of shift       |

</details>

<details>
<summary>void maid_mp_shr(size_t words, u32 *a, u64 shift);</summary>
Shifts a biginteger right

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of u32 words   |
| a     | Number to be shifted  |
| shift | Amount of shift       |

</details>

<details>
<summary>void maid_mp_mul(size_t words, u32 *a, const u32 *b,
                          u32 *tmp);</summary>
Multiplies a biginteger by another

### Parameters
| name  | description             |
|-------|-------------------------|
| words | Amount of u32 words     |
| a     | Multiplicand -> Product |
| b     | Multiplier (NULL = 1)   |
| tmp   | Temporary buffer        |

</details>

<details>
<summary>void maid_mp_div(size_t words, u32 *a, const u32 *b,
                          u32 *tmp, u32 *tmp2);</summary>
Divides a biginteger by another

### Parameters
| name  | description          |
|-------|----------------------|
| words | Amount of u32 words  |
| a     | Dividend -> Quotient |
| b     | Divisor (NULL = 1)   |
| tmp   | Temporary buffer 1   |
| tmp2  | Temporary buffer 2   |

</details>

<details>
<summary>void maid_mp_mod(size_t words, u32 *a, const u32 *b,
                          u32 *tmp, u32 *tmp2, u32 *tmp3);</summary>
Gets the remainder of a biginteger divided by another

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of u32 words   |
| a     | Dividend -> Remainder |
| b     | Divisor (NULL = 1)    |
| tmp   | Temporary buffer 1    |
| tmp2  | Temporary buffer 2    |
| tmp3  | Temporary buffer 3    |

</details>

<details>
<summary>void maid_mp_exp(size_t words, u32 *a, const u32 *b,
                          u32 *tmp, u32 *tmp2, u32 *tmp3);</summary>
Raises a big integer to the power of another

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of u32 words   |
| a     | Base -> Power         |
| b     | Exponent (NULL = 1)   |
| tmp   | Temporary buffer 1    |
| tmp2  | Temporary buffer 2    |
| tmp3  | Temporary buffer 3    |

</details>
