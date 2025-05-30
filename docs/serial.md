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

# Serialization

```c
#include <maid/serial.h>
```

## PEM Interface

<details>
<summary>enum maid_pem_t</summary>

| name                 | translation     |
|----------------------|-----------------|
| MAID_PEM_UNKNOWN     | (Unrecognized)  |
| MAID_PEM_PUBLIC_RSA  | RSA PUBLIC KEY  |
| MAID_PEM_PRIVATE_RSA | RSA PRIVATE KEY |
| MAID_PEM_PUBLIC      | PUBLIC KEY      |
| MAID_PEM_PRIVATE     | PRIVATE KEY     |
</details>

<details>
<summary>struct maid_pem</summary>

| field | description         |
|-------|---------------------|
| type  | Type of the header  |
| data  | Pointer to the data |
| size  | Size of the data    |
</details>

<details>
<summary>struct maid_pem *maid_pem_import(const char *input,
                                          const char **endptr)</summary>
Imports data from a PEM string (Skips comments)

### Parameters
| name    | description                   |
|---------|-------------------------------|
| input   | PEM-formatted string          |
| endptr  | Pointer to the last read byte |

### Return value
| case    | description       |
|---------|-------------------|
| Success | struct maid_pem * |
| Failure | NULL              |
</details>

<details>
<summary>char *maid_pem_export(struct maid_pem *p)</summary>
Exports data to a PEM string

### Parameters
| name | description         |
|------|---------------------|
| p    | Data to be exported |

### Return value
| case    | description          |
|---------|----------------------|
| Success | PEM-formatted string |
| Failure | NULL                 |
</details>

<details>
<summary>struct maid_pem *maid_pem_free(struct maid_pem *p)</summary>
Frees a maid_pem struct alocated by the library

### Parameters
| name | description         |
|------|---------------------|
| p    | Struct to be freed  |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

## Serial Interface

<details>
<summary>enum maid_serial</summary>

| name                          | description           | multiprecision integers                   |
|-------------------------------|-----------------------|-------------------------------------------|
| MAID_SERIAL_UNKNOWN           | (Unrecognized)        |                                           |
| MAID_SERIAL_RSA_PUBLIC        | PKCS1 RSA public key  | N, e                                      |
| MAID_SERIAL_RSA_PRIVATE       | PKCS1 RSA private key | N, e, d, p, q, d % p-1, d % q-1, q^-1 % p |
| MAID_SERIAL_PKCS8_RSA_PUBLIC  | PKCS8 RSA public key  | N, e                                      |
| MAID_SERIAL_PKCS8_RSA_PRIVATE | PKCS8 RSA private key | N, e, d, p, q, d % p-1, d % q-1, q^-1 % p |
</details>

<details>
<summary>enum maid_serial maid_serial_import(struct maid_pem *p, size_t *bits,
                                             maid_mp_word **output)</summary>
Imports a serialized object as ordered multiprecision integers

### Parameters
| name   | description                                     |
|--------|-------------------------------------------------|
| p      | Serialized object                               |
| bits   | Pointer to the bit count in each output integer |
| output | Array to store the output integer               |

### Return value
| case    | description         |
|---------|---------------------|
| Success | Type of the object  |
| Failure | MAID_SERIAL_UNKNOWN |

</details>

<details>
<summary>struct maid_pem *maid_serial_export(enum maid_serial s, size_t bits,
                                             maid_mp_word **input)</summary>
Exports ordered multiprecision integers as a serialized object

### Parameters
| name  | description                                  |
|-------|----------------------------------------------|
| s     | Type of the object                           |
| bits  | Bit count in each input integer              |
| input | Array that stores the input integer          |

### Return value
| case    | description       |
|---------|-------------------|
| Success | Serialized object |
| Failure | NULL              |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mp.h>
#include <maid/mem.h>

#include <maid/serial.h>

int main(void)
{
    char *key =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAzqwIgi3ssJW1AjCI\n"
        "eWCEy2SSOCTUPZamkxmD0bOLx60D9fbw4ongl9a1Zu2ehD6hqlNM1nqfxQSO2qVX\n"
        "o/SnnQIDAQABAkEAsaM4ZPwoNtdWj507kGgfe9rjuxIcwxsb7c++d54FhQdrpadU\n"
        "iUxgjQdxC9MSpW4w3w8N/ydO9WwJb5YK2aw3GQIhAOp+a1QbTadcZksx/3FGqi6T\n"
        "5J6RxDnogtBif7v4sgrrAiEA4aBltY2F7elx0shNvUtkTVyC2qst5PQia7HgGaqE\n"
        "5ZcCIH7seImo0aph8BiJcntMxXa6pEdUHQM/H/dNKViEL1KLAiEAthb33rTvwJkl\n"
        "VmJ3cuzUbybZKFb8PAnXeajdXnlitdMCIGap6SfPU5XLL+a1JqFjz3618hacJtv2\n"
        "v1Vb37O34dBo\n"
        "-----END PRIVATE KEY-----\n";

    struct maid_pem *p = maid_pem_import(key, NULL);
    if (p)
    {
        size_t bits = 0;
        maid_mp_word *params[8];

        if (maid_serial_import(p, &bits, params) ==
            MAID_SERIAL_PKCS8_RSA_PRIVATE)
        {
            struct maid_pem *p = NULL;
            char *s = NULL;

            p = maid_serial_export(MAID_SERIAL_RSA_PUBLIC, bits, params);
            if (p && (s = maid_pem_export(p)))
                printf("%s\n", s);
            maid_pem_free(p);
            free(s);

            p = maid_serial_export(MAID_SERIAL_RSA_PRIVATE, bits, params);
            if (p && (s = maid_pem_export(p)))
                printf("%s\n", s);
            maid_pem_free(p);
            free(s);
        }

        size_t words = maid_mp_words(bits);
        for (size_t i = 0; i < 8; i++)
        {
            maid_mem_clear(params[i], words * sizeof(maid_mp_word));
            free(params[i]);
        }
    }
    maid_pem_free(p);

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
