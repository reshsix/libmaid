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
#include <maid/rng.h>
```

## Internal Interface

<details>
<summary>struct maid_rng_def</summary>
Type that defines a RNG algorithm

</details>

## External Interface

<details>
<summary>maid_rng</summary>
Opaque type that contains the state of a RNG

</details>

<details>
<summary>maid_rng *maid_rng_new(struct maid_rng_def def,
                                const u8 *entropy)</summary>
Creates a RNG instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |
| entropy | Algorithm-dependent  |

### Return value
| case    | description       |
|---------|-------------------|
| Success | maid_rng instance |
| Failure | NULL              |

</details>

<details>
<summary>maid_rng *maid_rng_del(maid_rng *g)</summary>
Deletes a RNG instance

### Parameters
| name | description       |
|------|-------------------|
| g    | maid_rng instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_rng_renew(maid_rng *g, const u8 *entropy)</summary>
Recreates a RNG instance

### Parameters
| name    | description          |
|---------|----------------------|
| g       | maid_rng instance    |
| entropy | Algorithm-dependent  |

</details>

<details>
<summary>void maid_rng_generate(maid_rng *g, u8 *buffer,
                                size_t size)</summary>
Generates pseudorandom bytes

### Parameters
| name   | description             |
|--------|-------------------------|
| g      | maid_rng instance       |
| buffer | Memory to be written on |
| size   | Size of the operation   |

</details>

## External Algorithms

<details>
<summary>const struct maid_rng_def maid_ctr_drbg_aes_128</summary>
CTR-DRBG with AES-128 (NIST)

### Parameters
| name    | description |
|---------|-------------|
| entropy | 32 bytes    |
</details>

<details>
<summary>const struct maid_rng_def maid_ctr_drbg_aes_192</summary>
CTR-DRBG with AES-192 (NIST)

### Parameters
| name    | description |
|---------|-------------|
| entropy | 40 bytes    |
</details>

<details>
<summary>const struct maid_rng_def maid_ctr_drbg_aes_256</summary>
CTR-DRBG with AES-256 (NIST)

### Parameters
| name    | description |
|---------|-------------|
| entropy | 48 bytes    |
</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>

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

    maid_mem_clear(entropy, sizeof(entropy));

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
