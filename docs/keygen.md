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
#include <maid/mem.h>
#include <maid/rng.h>
#include <maid/serial.h>

#include <maid/keygen.h>

int main(void)
{
    /* Entropy needs to be a random or secret number instead*/
    u8 entropy[32] = {};
    maid_rng *g = maid_rng_new(maid_ctr_drbg_aes_128, entropy);

    maid_mp_word *params[8];
    size_t words = maid_keygen_rsa(2048, params, g);
    maid_mp_debug(stdout, words, "N",            params[0], false);
    maid_mp_debug(stdout, words, "e",            params[1], false);
    maid_mp_debug(stdout, words, "d",            params[2], false);
    maid_mp_debug(stdout, words, "p",            params[3], false);
    maid_mp_debug(stdout, words, "q",            params[4], false);
    maid_mp_debug(stdout, words, "d % (p - 1)",  params[5], false);
    maid_mp_debug(stdout, words, "d % (q - 1)",  params[6], false);
    maid_mp_debug(stdout, words, "q^-1 % p",     params[7], false);
    printf("\n");

    struct maid_pem *p = NULL;
    char *s = NULL;

    p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PUBLIC, 2048, params);
    if (p && (s = maid_pem_export(p)))
        printf("%s\n", s);
    maid_pem_free(p);
    free(s);

    p = maid_serial_export(MAID_SERIAL_PKCS8_RSA_PRIVATE, 2048, params);
    if (p && (s = maid_pem_export(p)))
        printf("%s\n", s);
    maid_pem_free(p);
    free(s);

    for (size_t i = 0; i < 8; i++)
    {
        maid_mem_clear(params[i], words * sizeof(maid_mp_word));
        free(params[i]);
    }

    maid_rng_del(g);
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
