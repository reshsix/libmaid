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
RSA public key, used in encryption and signature verification

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
RSA private key, used in decryption and signature generation

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

#include <maid/pub.h>

static u8 modulo[2048 / 8] =
    {0xce, 0xa8, 0x04, 0x75, 0x32, 0x4c, 0x1d, 0xc8, 0x34, 0x78, 0x27, 0x81,
     0x8d, 0xa5, 0x8b, 0xac, 0x06, 0x9d, 0x34, 0x19, 0xc6, 0x14, 0xa6, 0xea,
     0x1a, 0xc6, 0xa3, 0xb5, 0x10, 0xdc, 0xd7, 0x2c, 0xc5, 0x16, 0x95, 0x49,
     0x05, 0xe9, 0xfe, 0xf9, 0x08, 0xd4, 0x5e, 0x13, 0x00, 0x6a, 0xdf, 0x27,
     0xd4, 0x67, 0xa7, 0xd8, 0x3c, 0x11, 0x1d, 0x1a, 0x5d, 0xf1, 0x5e, 0xf2,
     0x93, 0x77, 0x1a, 0xef, 0xb9, 0x20, 0x03, 0x2a, 0x5b, 0xb9, 0x89, 0xf8,
     0xe4, 0xf5, 0xe1, 0xb0, 0x50, 0x93, 0xd3, 0xf1, 0x30, 0xf9, 0x84, 0xc0,
     0x7a, 0x77, 0x2a, 0x36, 0x83, 0xf4, 0xdc, 0x6f, 0xb2, 0x8a, 0x96, 0x81,
     0x5b, 0x32, 0x12, 0x3c, 0xcd, 0xd1, 0x39, 0x54, 0xf1, 0x9d, 0x5b, 0x8b,
     0x24, 0xa1, 0x03, 0xe7, 0x71, 0xa3, 0x4c, 0x32, 0x87, 0x55, 0xc6, 0x5e,
     0xd6, 0x4e, 0x19, 0x24, 0xff, 0xd0, 0x4d, 0x30, 0xb2, 0x14, 0x2c, 0xc2,
     0x62, 0xf6, 0xe0, 0x04, 0x8f, 0xef, 0x6d, 0xbc, 0x65, 0x2f, 0x21, 0x47,
     0x9e, 0xa1, 0xc4, 0xb1, 0xd6, 0x6d, 0x28, 0xf4, 0xd4, 0x6e, 0xf7, 0x18,
     0x5e, 0x39, 0x0c, 0xbf, 0xa2, 0xe0, 0x23, 0x80, 0x58, 0x2f, 0x31, 0x88,
     0xbb, 0x94, 0xeb, 0xbf, 0x05, 0xd3, 0x14, 0x87, 0xa0, 0x9a, 0xff, 0x01,
     0xfc, 0xbb, 0x4c, 0xd4, 0xbf, 0xd1, 0xf0, 0xa8, 0x33, 0xb3, 0x8c, 0x11,
     0x81, 0x3c, 0x84, 0x36, 0x0b, 0xb5, 0x3c, 0x7d, 0x44, 0x81, 0x03, 0x1c,
     0x40, 0xba, 0xd8, 0x71, 0x3b, 0xb6, 0xb8, 0x35, 0xcb, 0x08, 0x09, 0x8e,
     0xd1, 0x5b, 0xa3, 0x1e, 0xe4, 0xba, 0x72, 0x8a, 0x8c, 0x8e, 0x10, 0xf7,
     0x29, 0x4e, 0x1b, 0x41, 0x63, 0xb7, 0xae, 0xe5, 0x72, 0x77, 0xbf, 0xd8,
     0x81, 0xa6, 0xf9, 0xd4, 0x3e, 0x02, 0xc6, 0x92, 0x5a, 0xa3, 0xa0, 0x43,
     0xfb, 0x7f, 0xb7, 0x8d};

int main(void)
{
    /* 2048-bit textbook RSA as an example */

    size_t words = maid_mp_words(2048);

    maid_mp_word e[words];
    maid_mp_word N[words];

    maid_mp_mov(words, e, NULL);
    maid_mp_mov(words, N, NULL);

    e[0] = 65537;
    maid_mp_read(words, N, modulo, true);

    struct maid_rsa_key key = {.exponent = e, .modulo = N};

    u8 buf[2048 / 8] = {'t', 'e', 's', 't'};
    maid_pub *p = maid_pub_new(maid_rsa_public, &key, 2048);
    if (p)
        maid_pub_apply(p, buf);
    maid_pub_del(p);

    for (size_t i = 0; i < sizeof(buf); i++)
        printf("%02x", buf[i]);
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
