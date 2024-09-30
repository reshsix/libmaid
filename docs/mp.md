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

# Multiprecision Utils

```c
#include <maid/mp.h>
```

Words are used in a little-endian way

Temporary values are not cleared by the end of functions

<details>
<summary>maid_mp_word</summary>
Type that contains a word: u64 on systems with 128-bits integer support,
otherwise u32
</details>

<details>
<summary>size_t maid_mp_words(size_t bits);</summary>
Returns minimal amount of words for a quantity of bits

### Parameters
| name | description    |
|------|----------------|
| bits | Amount of bits |

### Return value
| case   | description     |
|--------|-----------------|
| Always | Amount of words |

</details>

<details>
<summary>void maid_mp_read(size_t words, maid_mp_word *a,
                           const u8 *addr, bool big);</summary>
Reads a biginteger from memory

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of words     |
| a     | Destination         |
| addr  | Memory to read      |
| big   | Little/Big endian   |

</details>

<details>
<summary>void maid_mp_write(size_t words, const maid_mp_word *a,
                            u8 *addr, bool big);</summary>
Writes a biginteger to memory

### Parameters
| name  | description          |
|-------|----------------------|
| words | Amount of words      |
| a     | Source               |
| addr  | Memory to be written |
| big   | Little/Big endian    |

</details>

<details>
<summary>void maid_mp_debug(size_t words, const char *name,
                            const maid_mp_word *a);</summary>
Prints a biginteger

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of words     |
| name  | Name to print       |
| a     | Number to print     |

</details>

<details>
<summary>void maid_mp_not(size_t words, maid_mp_word *a);</summary>
Binary NOTs a biginteger

### Parameters
| name  | description        |
|-------|--------------------|
| words | Amount of words    |
| a     | Destination        |

</details>

<details>
<summary>void maid_mp_and(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Binary ANDs a biginteger to another

### Parameters
| name  | description        |
|-------|--------------------|
| words | Amount of words    |
| a     | Destination        |
| b     | Source (NULL = -1) |

</details>

<details>
<summary>void maid_mp_orr(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Binary ORs a biginteger to another

### Parameters
| name  | description       |
|-------|-------------------|
| words | Amount of words   |
| a     | Destination       |
| b     | Source (NULL = 0) |

</details>

<details>
<summary>void maid_mp_xor(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Binary XORs a biginteger to another

### Parameters
| name  | description       |
|-------|-------------------|
| words | Amount of words   |
| a     | Destination       |
| b     | Source (NULL = 0) |

</details>

<details>
<summary>s8 maid_mp_cmp(size_t words, const maid_mp_word *a,
                        const maid_mp_word *b);</summary>
Compares two bigintegers

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of words     |
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
<summary>void maid_mp_mov(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Sets a biginteger to another

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of words     |
| a     | Destination         |
| b     | Source (NULL = 0)   |

</details>

<details>
<summary>void maid_mp_add(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Adds a biginteger to another

### Parameters
| name  | description         |
|-------|---------------------|
| words | Amount of words     |
| a     | Augend -> Total     |
| b     | Addend (NULL = 0)   |

</details>

<details>
<summary>void maid_mp_sub(size_t words, maid_mp_word *a,
                          const maid_mp_word *b);</summary>
Subtracts a biginteger from another

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of words       |
| a     | Minuend -> Difference |
| b     | Subtrahend (NULL = 0) |

</details>

<details>
<summary>void maid_mp_shl(size_t words, maid_mp_word *a, u64 shift);</summary>
Shifts a biginteger left

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of words       |
| a     | Number to be shifted  |
| shift | Amount of shift       |

</details>

<details>
<summary>void maid_mp_shr(size_t words, maid_mp_word *a, u64 shift);</summary>
Shifts a biginteger right

### Parameters
| name  | description           |
|-------|-----------------------|
| words | Amount of words       |
| a     | Number to be shifted  |
| shift | Amount of shift       |

</details>

<details>
<summary>void maid_mp_mul(size_t words, maid_mp_word *a,
                          const maid_mp_word *b, maid_mp_word *tmp);</summary>
Multiplies a biginteger by another

### Parameters
| name  | description              |
|-------|--------------------------|
| words | Amount of words          |
| a     | Multiplicand -> Product  |
| b     | Multiplier (NULL = 1)    |
| tmp   | Temporary buffer (words) |

</details>

<details>
<summary>void maid_mp_div(size_t words, maid_mp_word *a,
                          const maid_mp_word *b, maid_mp_word *tmp);</summary>
Divides a biginteger by another

### Parameters
| name  | description                  |
|-------|------------------------------|
| words | Amount of words              |
| a     | Dividend -> Quotient         |
| b     | Divisor (NULL = 1)           |
| tmp   | Temporary buffer (words * 2) |

</details>

<details>
<summary>void maid_mp_mod(size_t words, maid_mp_word *a,
                          const maid_mp_word *b, maid_mp_word *tmp);</summary>
Gets the remainder of a biginteger divided by another

### Parameters
| name  | description                  |
|-------|------------------------------|
| words | Amount of words              |
| a     | Dividend -> Remainder        |
| b     | Divisor (NULL = 1)           |
| tmp   | Temporary buffer (words * 3) |

</details>

<details>
<summary>void maid_mp_exp(size_t words, maid_mp_word *a,
                          const maid_mp_word *b, maid_mp_word *tmp);</summary>
Raises a big integer to the power of another

### Parameters
| name  | description                  |
|-------|------------------------------|
| words | Amount of words              |
| a     | Base -> Power                |
| b     | Exponent (NULL = 1)          |
| tmp   | Temporary buffer (words * 3) |

</details>

<details>
<summary>void maid_mp_div2(size_t words, maid_mp_word *a,
                           maid_mp_word *rem, const maid_mp_word *b,
                           maid_mp_word *tmp);</summary>
Divides a biginteger by another, and returns the remainder

### Parameters
| name  | description                  |
|-------|------------------------------|
| words | Amount of words              |
| a     | Dividend -> Quotient         |
| rem   | Remainder                    |
| b     | Divisor (NULL = 1)           |
| tmp   | Temporary buffer (words * 2) |

</details>

<details>
<summary>void maid_mp_mulmod(size_t words, maid_mp_word *a,
                             const maid_mp_word *b, const maid_mp_word *mod,
                             maid_mp_word *tmp);</summary>
Modular multiplies a biginteger by another

### Parameters
| name  | description                   |
|-------|-------------------------------|
| words | Amount of words               |
| a     | Multiplicand -> Product       |
| b     | Multiplier (NULL = 1)         |
| mod   | Modulo divisor                |
| tmp   | Temporary buffer (words * 12) |

</details>

<details>
<summary>void maid_mp_expmod(size_t words, maid_mp_word *a,
                             const maid_mp_word *b, const maid_mp_word *mod,
                             maid_mp_word *tmp);</summary>
Raises a big integer to the modular power of another

### Parameters
| name  | description                   |
|-------|-------------------------------|
| words | Amount of words               |
| a     | Base -> Power                 |
| b     | Exponent (NULL = 1)           |
| mod   | Modulo divisor                |
| tmp   | Temporary buffer (words * 14) |

</details>

<details>
<summary>bool maid_mp_invmod(size_t words, maid_mp_word *a,
                             const maid_mp_word *mod,
                             maid_mp_word *tmp);</summary>
Modular multiplicative inverse of a biginteger

### Parameters
| name  | description                   |
|-------|-------------------------------|
| words | Amount of words               |
| a     | Number                        |
| mod   | Modulo divisor                |
| tmp   | Temporary buffer (words * 21) |

### Return value
| case           | description |
|----------------|-------------|
| Exists         | true        |
| Doesn't exist  | false       |

</details>

<details>
<summary>void maid_mp_expmod2(size_t words, maid_mp_word *a,
                              const maid_mp_word *b, const maid_mp_word *mod,
                              maid_mp_word *tmp);</summary>
Raises a big integer to the modular power of another (using Montgomery method)

### Parameters
| name  | description                   |
|-------|-------------------------------|
| words | Amount of words               |
| a     | Base -> Power                 |
| b     | Exponent (NULL = 1)           |
| mod   | Odd modulo divisor            |
| tmp   | Temporary buffer (words * 49) |

</details>
