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

# Key generation

```c
#include <maid/keygen.h>
```

## External Interface

<details>
<summary>size_t maid_keygen_rsa(size_t bits, maid_mp_word **output,
                                maid_rng *g)</summary>
Generates a RSA key

### Parameters
| name    | description                                           |
|---------|-------------------------------------------------------|
| bits    | Bit length of the key                                 |
| output  | Array of {N, e, d, p, q, d % p-1, d % q-1, q^-1 % p}  |
| g       | maid_rng instance                                     |

### Return value
| case    | description         |
|---------|---------------------|
| Success | maid_mp_words(bits) |
| Failure | 0                   |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mp.h>
#include <maid/rng.h>
#include <maid/keygen.h>
#include <maid/serial.h>

int main(void)
{
    /* Entropy needs to be a random or secret number instead*/
    u8 entropy[32] = {};
    maid_rng *g = maid_rng_new(maid_ctr_drbg_aes_128, entropy);

    maid_mp_word *params[8];
    size_t words = maid_keygen_rsa(2048, params, g);
    maid_mp_debug(words, "N",            params[0], false);
    maid_mp_debug(words, "e",            params[1], false);
    maid_mp_debug(words, "d",            params[2], false);
    maid_mp_debug(words, "p",            params[3], false);
    maid_mp_debug(words, "q",            params[4], false);
    maid_mp_debug(words, "d % (p - 1)",  params[5], false);
    maid_mp_debug(words, "d % (q - 1)",  params[6], false);
    maid_mp_debug(words, "q^-1 % p",     params[7], false);
    printf("\n");

    struct maid_pem *p = NULL;
    p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PUBLIC, 2048, params);
    if (p)
        printf("%s\n", maid_pem_export(p));
    free(p);

    p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PRIVATE, 2048, params);
    if (p)
        printf("%s\n", maid_pem_export(p));
    free(p);

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
