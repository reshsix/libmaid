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
#include <maid/mac.h>
```

## Internal Interface

<details>
<summary>struct maid_mac_def</summary>
Type that defines a MAC algorithm

</details>

## Internal Algorithms

<details>
<summary>struct maid_mac_def maid_gcm</summary>
Special MAC for GCM AEAD construction
</details>

## External Interface

<details>
<summary>maid_mac</summary>
Opaque type that contains the state of a MAC

</details>

<details>
<summary>maid_mac *maid_mac_new(struct maid_mac_def def,
                                const u8 *key)</summary>
Creates a MAC instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |
| key     | Algorithm-dependent  |

### Return value
| case    | description       |
|---------|-------------------|
| Success | maid_mac instance |
| Failure | NULL              |

</details>

<details>
<summary>maid_mac *maid_mac_del(maid_mac *m)</summary>
Deletes a MAC instance

### Parameters
| name | description       |
|------|-------------------|
| m    | maid_mac instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_mac_renew(maid_mac *m, const u8 *key)</summary>
Recreates a MAC instance

### Parameters
| name    | description          |
|---------|----------------------|
| m       | maid_mac instance    |
| key     | Algorithm-dependent  |

</details>

<details>
<summary>void maid_mac_update(maid_mac *m,
                              const u8 *buffer, size_t size)</summary>
Updates the MAC state

### Parameters
| name   | description           |
|--------|-----------------------|
| m      | maid_mac instance     |
| buffer | Data to be read       |
| size   | Size of the operation |

</details>

<details>
<summary>void maid_mac_digest(maid_mac *m, u8 *output)</summary>
Outputs the authentication tag (One time, ending the MAC instance)

### Parameters
| name   | description            |
|--------|------------------------|
| m      | maid_mac instance      |
| output | Block to be written on |

</details>

## External Algorithms

<details>
<summary>const struct maid_mac_def maid_poly1305</summary>
Poly1305 128-bit MAC (IETF)

### Parameters
| name | description |
|------|-------------|
| key  | 256-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha224</summary>
HMAC-SHA224 224-bit MAC (NIST)

### Parameters
| name | description |
|------|-------------|
| key  | 512-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha256</summary>
HMAC-SHA256 256-bit MAC (NIST)

### Parameters
| name | description |
|------|-------------|
| key  | 512-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha384</summary>
HMAC-SHA384 384-bit MAC (NIST)

### Parameters
| name | description  |
|------|--------------|
| key  | 1024-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha512</summary>
HMAC-SHA512 512-bit MAC (NIST)

### Parameters
| name | description  |
|------|--------------|
| key  | 1024-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha512_224</summary>
HMAC-SHA512/224 224-bit MAC (NIST)

### Parameters
| name | description  |
|------|--------------|
| key  | 1024-bit key |
</details>

<details>
<summary>const struct maid_mac_def maid_hmac_sha512_256</summary>
HMAC-SHA512/256 256-bit MAC (NIST)

### Parameters
| name | description  |
|------|--------------|
| key  | 1024-bit key |
</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>

#include <maid/mac.h>

int main(void)
{
    int ret = EXIT_FAILURE;

    u8  key[32] = {0};
    u8 data[64] = {0};
    u8  tag[16] = {0};
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = i;

    maid_mac *m = maid_mac_new(maid_poly1305, key);
    if (m)
    {
        maid_mac_update(m, data, sizeof(data));
        maid_mac_digest(m, tag);

        for (size_t i = 0; i < sizeof(tag); i++)
            printf("%02x", tag[i]);
        printf("\n");

        ret = EXIT_SUCCESS;
    }
    else
        fprintf(stderr, "Out of memory\n");
    maid_mac_del(m);

    maid_mem_clear(key, sizeof(key));

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
