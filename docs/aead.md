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

# Authenticated Encryption (with Additional Data)

```c
#include <maid/aead.h>
```

## Internal Interface

<details>
<summary>struct maid_aead_def</summary>
Type that defines a AEAD construction

</details>

## External Interface

<details>
<summary>maid_aead</summary>
Opaque type that contains the state of a AEAD

</details>

<details>
<summary>maid_aead *maid_aead_new(struct maid_aead_def def,
                                  const u8 *restrict key,
                                  const u8 *restrict nonce)</summary>
Creates an AEAD instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |
| key     | Algorithm-dependent  |
| nonce   | Algorithm-dependent  |

### Return value
| case    | description        |
|---------|--------------------|
| Success | maid_aead instance |
| Failure | NULL               |

</details>

<details>
<summary>maid_aead *maid_aead_del(maid_aead *ae)</summary>
Deletes an AEAD instance

### Parameters
| name | description        |
|------|--------------------|
| ae   | maid_aead instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_aead_renew(maid_aead *ae, const u8 *restrict key,
                              const u8 *restrict nonce)</summary>
Recreates an AEAD instance

### Parameters
| name    | description          |
|---------|----------------------|
| ae      | maid_aead instance   |
| key     | Algorithm-dependent  |
| nonce   | Algorithm-dependent  |

</details>

<details>
<summary>void maid_aead_update(maid_aead *ae,
                               const u8 *buffer, size_t size)</summary>
Updates the AEAD state with additional data (Step 1)

### Parameters
| name   | description           |
|--------|-----------------------|
| ae     | maid_aead instance    |
| buffer | Data to be read       |
| size   | Size of the operation |

</details>

<details>
<summary>void maid_aead_crypt(maid_aead *ae,
                              u8 *buffer, size_t size, bool decrypt)</summary>
Encrypts/Decrypts data, and updates the AEAD state (Step 2, locks Step 1)

### Parameters
| name    | description               |
|---------|---------------------------|
| ae      | maid_aead instance        |
| buffer  | Memory to be ciphered     |
| size    | Size of the operation     |
| decrypt | Encrypt/Decrypt operation |

</details>

<details>
<summary>void maid_aead_digest(maid_aead *ae, u8 *output)</summary>
Outputs the authentication tag (Step 3, ending the AEAD instance)

### Parameters
| name   | description            |
|--------|------------------------|
| ae     | maid_aead instance     |
| output | Block to be written on |

</details>

## External Algorithms

<details>
<summary>const struct maid_aead_def maid_aes_gcm_128</summary>
AES-128 on GCM mode (NIST)

### Parameters
| name   | description  |
|--------|--------------|
| key    | 128-bit key  |
| nonce  | 96-bit nonce |
</details>

<details>
<summary>const struct maid_aead_def maid_aes_gcm_192</summary>
AES-192 on GCM mode (NIST)

### Parameters
| name   | description  |
|--------|--------------|
| key    | 192-bit key  |
| nonce  | 96-bit nonce |
</details>

<details>
<summary>const struct maid_aead_def maid_aes_gcm_256</summary>
AES-256 on GCM mode (NIST)

### Parameters
| name   | description  |
|--------|--------------|
| key    | 256-bit key  |
| nonce  | 96-bit nonce |
</details>

<details>
<summary>const struct maid_aead_def maid_chacha20poly1305</summary>
Chacha20 with Poly1305 (IETF)

### Parameters
| name   | description  |
|--------|--------------|
| key    | 256-bit key  |
| nonce  | 96-bit nonce |
</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>

#include <maid/aead.h>

int main(void)
{
    int ret = EXIT_FAILURE;

    u8  key[32] = {0};
    u8   iv[12] = {0};
    u8 data[64] = {0};
    u8  aad[32] = {0};
    u8  tag[16] = {0};
    u8 tag2[16] = {0};

    maid_aead *ae = maid_aead_new(maid_aes_gcm_256, key, iv);
    if (ae)
    {
        /* Encryption */

        maid_aead_update(ae, aad, sizeof(aad));
        maid_aead_crypt(ae, data, sizeof(data), false);
        maid_aead_digest(ae, tag);

        for (size_t i = 0; i < sizeof(data); i++)
            printf("%02x", data[i]);
        printf("\n");

        for (size_t i = 0; i < sizeof(tag); i++)
            printf("%02x", tag[i]);
        printf("\n");

        /* Decryption */

        maid_aead_renew(ae, key, iv);

        maid_aead_update(ae, aad, sizeof(aad));
        maid_aead_crypt(ae, data, sizeof(data), true);
        maid_aead_digest(ae, tag2);

        for (size_t i = 0; i < sizeof(data); i++)
            printf("%02x", data[i]);
        printf("\n");

        for (size_t i = 0; i < sizeof(tag2); i++)
            printf("%02x", tag2[i]);
        printf("\n");

        ret = EXIT_SUCCESS;
    }
    else
        fprintf(stderr, "Out of memory\n");
    maid_aead_del(ae);

    maid_mem_clear(key,  sizeof(key));
    maid_mem_clear(data, sizeof(data));

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
