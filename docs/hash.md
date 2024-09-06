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
#include <maid/hash.h>
```

## Internal Interface

<details>
<summary>struct maid_hash_def</summary>
Type that defines a hash function

</details>

## External Interface

<details>
<summary>maid_hash</summary>
Opaque type that contains the state of a hash function

</details>

<details>
<summary>maid_hash *maid_hash_new(struct maid_hash_def def)</summary>
Creates a hash function instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |

### Return value
| case    | description        |
|---------|--------------------|
| Success | maid_hash instance |
| Failure | NULL               |

</details>

<details>
<summary>maid_hash *maid_hash_del(maid_hash *h)</summary>
Deletes a hash function instance

### Parameters
| name | description        |
|------|--------------------|
| h    | maid_hash instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_hash_renew(maid_hash *h)</summary>
Recreates a hash function instance

### Parameters
| name    | description          |
|---------|----------------------|
| h       | maid_hash instance   |

</details>

<details>
<summary>void maid_hash_update(maid_hash *h,
                               const u8 *buffer, size_t size)</summary>
Updates the hash function state

### Parameters
| name   | description            |
|--------|------------------------|
| h      | maid_hash instance     |
| buffer | Data to be read        |
| size   | Size of the operation  |

</details>

<details>
<summary>void maid_hash_digest(maid_hash *h, u8 *output)</summary>
Outputs the hash (One time, ending the hash function instance)

### Parameters
| name   | description            |
|--------|------------------------|
| h      | maid_hash instance     |
| output | Block to be written on |

</details>

## External Algorithms

<details>
<summary>const struct maid_hash_def maid_sha224</summary>
SHA-2 224-bits hash (NIST)
</details>

<details>
<summary>const struct maid_hash_def maid_sha256</summary>
SHA-2 256-bits hash (NIST)
</details>

<details>
<summary>const struct maid_hash_def maid_sha384</summary>
SHA-2 384-bits hash (NIST)
</details>

<details>
<summary>const struct maid_hash_def maid_sha512</summary>
SHA-2 512-bits hash (NIST)
</details>

<details>
<summary>const struct maid_hash_def maid_sha512_244</summary>
SHA-2 512-bits hash, truncated to 224-bits (NIST)
</details>

<details>
<summary>const struct maid_hash_def maid_sha512_256</summary>
SHA-2 512-bits hash, truncated to 256-bits (NIST)
</details>

## Example Code

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
