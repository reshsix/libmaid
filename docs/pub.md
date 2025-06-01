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

# Public-key primitives

```c
#include <maid/pub.h>
```

## Internal Interface

<details>
<summary>struct maid_pub_def</summary>
Type that defines a public-key primitive

</details>

## External Interface

<details>
<summary>maid_pub</summary>
Opaque type that contains the state of a public-key primitive

</details>

<details>
<summary>maid_pub *maid_pub_new(struct maid_pub_def def,
                                const void *key, size_t bits)</summary>
Creates a public-key primitive instance

### Parameters
| name | description          |
|------|----------------------|
| def  | Algorithm definition |
| key  | Algorithm-dependent  |
| bits | Algorithm-dependent  |

### Return value
| case    | description       |
|---------|-------------------|
| Success | maid_pub instance |
| Failure | NULL              |

</details>

<details>
<summary>maid_pub *maid_pub_del(maid_pub *p)</summary>
Deletes a public-key primitive instance

### Parameters
| name | description       |
|------|-------------------|
| p    | maid_pub instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_pub_renew(maid_pub *p, const void *key)</summary>
Recreates a public-key primitive instance

### Parameters
| name | description         |
|------|---------------------|
| p    | maid_pub instance   |
| key  | Algorithm-dependent |

</details>

<details>
<summary>void maid_pub_apply(maid_pub *p, u8 *buffer)</summary>
Applies a public-key primitive

### Parameters
| name   | description           |
|--------|-----------------------|
| p      | maid_pub instance     |
| buffer | Block to be processed |

</details>

## External Algorithms

<details>
<summary>struct maid_rsa_key</summary>
Used for both RSA public and private keys

### Parameters

| name     | description          |
|----------|----------------------|
| exponent | public e / private d |
| modulo   | modulo N (p * q)     |

</details>

<details>
<summary>const struct maid_pub_def maid_rsa_public</summary>
RSA public key (RSA Security)

### Parameters

#### maid_pub_new
| name | description                       |
|------|-----------------------------------|
| key  | struct maid_rsa_key *             |
| bits | Multiple of maid_mp_word bit size |

#### maid_pub_apply
| name   | description       |
|--------|-------------------|
| buffer | bits sized buffer |

</details>

<details>
<summary>const struct maid_pub_def maid_rsa_private</summary>
RSA private key (RSA Security)

### Parameters

#### maid_pub_new
| name | description                       |
|------|-----------------------------------|
| key  | struct maid_rsa_key *             |
| bits | Multiple of maid_mp_word bit size |

#### maid_pub_apply
| name   | description       |
|--------|-------------------|
| buffer | bits sized buffer |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>
#include <maid/serial.h>

#include <maid/pub.h>

int main(void)
{
    int ret = EXIT_FAILURE;

    /* 2048-bit textbook RSA as an example */

    const char *key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBDstz7BoLRNCLY+m7zJGka\n"
        "pVzGW3624kNmqshbeir6os6tIlUN6Zgisfc5ZEN/jILa7ayOwz7yqZ4jQwEtow9q\n"
        "cdFtpbiN7EyJq0q5m/jqvm3uf8Rj/r8wKZ0mZ9WjgPyU9qWqNY/kz69KgztOU2wf\n"
        "jDGUFTQlcpnSBpEaSophY+JvgnN+Ems+aCVn5mJ0KeSBBOJa+ZnIqG5uMPE5nI16\n"
        "YI3EJ94QNkRRmRQohZSmnElahs9DsS5/sKAC6zHR+Im5rUUbRe4V6HEgT0jJ7NNU\n"
        "MrfEKbzfYofCK3tq7El1s7jYIHvY1JerwBpO+zHwGozbijidbsOTblc900sl/lpl\n"
        "AgMBAAE=\n"
        "-----END PUBLIC KEY-----\n";

    struct maid_pem *p = maid_pem_import(key, NULL);
    if (p)
    {
        size_t bits = 0;
        maid_mp_word *params[2];

        if (maid_serial_import(p, &bits, params) ==
            MAID_SERIAL_PKCS8_RSA_PUBLIC)
        {
            struct maid_rsa_key key = {.exponent = params[1],
                                       .modulo   = params[0]};

            u8 buf[2048 / 8] = {'t', 'e', 's', 't'};
            maid_pub *p = maid_pub_new(maid_rsa_public, &key, 2048);
            if (p)
                maid_pub_apply(p, buf);
            else
                fprintf(stderr, "Out of memory\n");
            maid_pub_del(p);

            for (size_t i = 0; i < sizeof(buf); i++)
                printf("%02x", buf[i]);
            printf("\n");

            ret = EXIT_SUCCESS;
        }
        else
            fprintf(stderr, "Not a PKCS8 RSA Public key\n");

        size_t words = maid_mp_words(bits);
        for (size_t i = 0; i < 2; i++)
            free(params[i]);
    }
    else
        fprintf(stderr, "Failed to read PEM data\n");
    maid_pem_free(p);

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
