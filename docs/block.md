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
#include <maid/block.h>
```

## Internal Interface

<details>
<summary>struct maid_block_def</summary>
Type that defines a block cipher algorithm

</details>

## External Interface

<details>
<summary>maid_block</summary>
Opaque type that contains the state of a block cipher

</details>

<details>
<summary>maid_block *maid_block_new(struct maid_block_def def,
                                    const u8 *restrict key,
                                    const u8 *restrict iv)</summary>
Creates a block cipher instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |
| key     | Algorithm-dependent  |
| iv      | Algorithm-dependent  |

### Return value
| case    | description         |
|---------|---------------------|
| Success | maid_block instance |
| Failure | NULL                |

</details>

<details>
<summary>maid_block *maid_block_del(maid_block *bl)</summary>
Deletes a block cipher instance

### Parameters
| name | description         |
|------|---------------------|
| bl   | maid_block instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_block_renew(maid_block *bl,const u8 *restrict key,
                               const u8 *restrict iv)</summary>
Recreates a block cipher instance

### Parameters
| name    | description          |
|---------|----------------------|
| bl      | maid_block instance  |
| key     | Algorithm-dependent  |
| iv      | Algorithm-dependent  |

</details>

<details>
<summary>void maid_block_ecb(maid_block *bl,
                             u8 *buffer, bool decrypt)</summary>
Applies ECB mode (doesn't change the iv)

### Parameters
| name    | description               |
|---------|---------------------------|
| bl      | maid_block instance       |
| buffer  | Block to be ciphered      |
| decrypt | Encrypt/Decrypt operation |

</details>

<details>
<summary>void maid_block_ecb(maid_block *bl,
                             u8 *buffer, size_t size)</summary>
Applies CTR mode (increases iv accordingly)

### Parameters
| name   | description           |
|--------|-----------------------|
| bl     | maid_block instance   |
| buffer | Memory to be ciphered |
| size   | Size of the operation |

</details>

## External Algorithms

<details>
<summary>struct maid_block_def maid_aes_128</summary>
AES-128 block cipher (NIST)

### Parameters
| name | description |
|------|-------------|
| key  | 128-bit key |
| iv   | 128-bit iv  |
</details>

<details>
<summary>struct maid_block_def maid_aes_192</summary>
AES-192 block cipher (NIST)

### Parameters
| name | description |
|------|-------------|
| key  | 192-bit key |
| iv   | 128-bit iv  |
</details>

<details>
<summary>struct maid_block_def maid_aes_256</summary>
AES-256 block cipher (NIST)

### Parameters
| name | description |
|------|-------------|
| key  | 256-bit key |
| iv   | 128-bit iv  |
</details>
