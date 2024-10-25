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

# Digital signatures

```c
#include <maid/sign.h>
```

## Internal Interface

<details>
<summary>struct maid_sign_def</summary>
Type that defines a digital signature algorithm

</details>

## External Interface

<details>
<summary>maid_sign</summary>
Opaque type that contains the state of a digital signature

</details>

<details>
<summary>maid_sign *maid_sign_new(struct maid_sign_def def, maid_pub *public,
                                  maid_pub *private, size_t bits)</summary>
Creates a digital signature instance

### Parameters
| name    | description                 |
|---------|-----------------------------|
| def     | Algorithm definition        |
| public  | Public key for verification |
| private | Private key for generation  |
| bits    | Bit length of the keys      |

### Return value
| case    | description        |
|---------|--------------------|
| Success | maid_sign instance |
| Failure | NULL               |

</details>

<details>
<summary>maid_sign *maid_sign_del(maid_sign *s)</summary>
Deletes a digital signature instance

### Parameters
| name | description        |
|------|--------------------|
| s    | maid_sign instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_sign_renew(maid_sign *s, const *void key)</summary>
Recreates a digital signature instance

### Parameters
| name    | description                 |
|---------|-----------------------------|
| s       | maid_sign instance          |
| public  | Public key for verification |
| private | Private key for generation  |

</details>

<details>
<summary>void maid_sign_generate(maid_sign *s, u8 *buffer)</summary>
Generates a digital signature

### Parameters
| name   | description        |
|--------|--------------------|
| s      | maid_sign instance |
| buffer | Hash -> Signature  |

</details>

<details>
<summary>bool maid_sign_verify(maid_sign *s, u8 *buffer)</summary>
Verifies a digital signature

### Parameters
| name   | description        |
|--------|--------------------|
| s      | maid_sign instance |
| buffer | Signature -> Hash  |

### Return value
| case    | description |
|---------|-------------|
| Valid   | true        |
| Invalid | false       |

</details>

## External Algorithms

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha224</summary>
PKCS#1 v1.5 signature with SHA-224

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 224-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 224-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha256</summary>
PKCS#1 v1.5 signature with SHA-256

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 256-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 256-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha384</summary>
PKCS#1 v1.5 signature with SHA-384

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 384-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 384-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha512</summary>
PKCS#1 v1.5 signature with SHA-512

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 512-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 512-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha512_224</summary>
PKCS#1 v1.5 signature with SHA-512/224

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 224-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 224-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha512_256</summary>
PKCS#1 v1.5 signature with SHA-512/256

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 256-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 256-bits |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>
#include <maid/pub.h>
#include <maid/sign.h>

static u8 hash[256 / 8] =
    {0x07, 0x78, 0x77, 0x89, 0x5a, 0x42, 0x80, 0x28, 0xf6, 0x09, 0x98, 0xb9,
     0x85, 0x55, 0x08, 0x20, 0x02, 0x5a, 0x2a, 0x42, 0xc0, 0xbe, 0xab, 0x27,
     0x16, 0x5c, 0x08, 0x02, 0xd3, 0x09, 0x81, 0x50};

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

static u8 signature[2048 / 8] =
    {0x6b, 0x8b, 0xe9, 0x7d, 0x9e, 0x51, 0x8a, 0x2e, 0xde, 0x74, 0x6f, 0xf4,
     0xa7, 0xd9, 0x1a, 0x84, 0xa1, 0xfc, 0x66, 0x5b, 0x52, 0xf1, 0x54, 0xa9,
     0x27, 0x65, 0x0d, 0xb6, 0xe7, 0x34, 0x8c, 0x69, 0xf8, 0xc8, 0x88, 0x1f,
     0x7b, 0xcf, 0x9b, 0x1a, 0x6d, 0x33, 0x66, 0xee, 0xd3, 0x0c, 0x3a, 0xed,
     0x4e, 0x93, 0xc2, 0x03, 0xc4, 0x3f, 0x55, 0x28, 0xa4, 0x5d, 0xe7, 0x91,
     0x89, 0x57, 0x47, 0xad, 0xe9, 0xc5, 0xfa, 0x5e, 0xee, 0x81, 0x42, 0x7e,
     0xde, 0xe0, 0x20, 0x82, 0x14, 0x7a, 0xa3, 0x11, 0x71, 0x2a, 0x6a, 0xd5,
     0xfb, 0x17, 0x32, 0xe9, 0x3b, 0x3d, 0x6c, 0xd2, 0x3f, 0xfd, 0x46, 0xa0,
     0xb3, 0xca, 0xf6, 0x2a, 0x8b, 0x69, 0x95, 0x7c, 0xc6, 0x8a, 0xe3, 0x9f,
     0x99, 0x93, 0xc1, 0xa7, 0x79, 0x59, 0x9c, 0xdd, 0xa9, 0x49, 0xbd, 0xaa,
     0xba, 0xbb, 0x77, 0xf2, 0x48, 0xfc, 0xfe, 0xaa, 0x44, 0x05, 0x9b, 0xe5,
     0x45, 0x9f, 0xb9, 0xb8, 0x99, 0x27, 0x8e, 0x92, 0x95, 0x28, 0xee, 0x13,
     0x0f, 0xac, 0xd5, 0x33, 0x72, 0xec, 0xbc, 0x42, 0xf3, 0xe8, 0xde, 0x29,
     0x98, 0x42, 0x58, 0x60, 0x40, 0x64, 0x40, 0xf2, 0x48, 0xd8, 0x17, 0x43,
     0x2d, 0xe6, 0x87, 0x11, 0x2e, 0x50, 0x4d, 0x73, 0x40, 0x28, 0xe6, 0xc5,
     0x62, 0x0f, 0xa2, 0x82, 0xca, 0x07, 0x64, 0x70, 0x06, 0xcf, 0x0a, 0x2f,
     0xf8, 0x3e, 0x19, 0xa9, 0x16, 0x55, 0x4c, 0xc6, 0x18, 0x10, 0xc2, 0xe8,
     0x55, 0x30, 0x5d, 0xb4, 0xe5, 0xcf, 0x89, 0x3a, 0x6a, 0x96, 0x76, 0x73,
     0x65, 0x79, 0x45, 0x56, 0xff, 0x03, 0x33, 0x59, 0x08, 0x4d, 0x7e, 0x38,
     0xa8, 0x45, 0x6e, 0x68, 0xe2, 0x11, 0x55, 0xb7, 0x61, 0x51, 0x31, 0x4a,
     0x29, 0x87, 0x5f, 0xee, 0xe0, 0x95, 0x57, 0x16, 0x1c, 0xbc, 0x65, 0x45,
     0x41, 0xe8, 0x9e, 0x42};

int main(void)
{
    size_t words = maid_mp_words(2048);

    maid_mp_word e[words];
    maid_mp_word N[words];

    maid_mp_mov(words, e, NULL);
    maid_mp_mov(words, N, NULL);

    e[0] = 0x260445;
    maid_mp_read(words, N, modulo, true);

    struct maid_rsa_key pubkey = {.exponent = e, .modulo = N};
    maid_pub *pub = maid_pub_new(maid_rsa_public, &pubkey, 2048);

    maid_sign *s = maid_sign_new(maid_pkcs1_v1_5_sha256, pub, NULL, 2048);
    if (s)
    {
        u8 buf[2048 / 8] = {0};
        if (maid_sign_verify(s, buf) && maid_mem_cmp(buf, hash, 256 / 8))
            printf("Valid!\n");
        else
            printf("Invalid!\n");

        for (size_t i = 0; i < sizeof(hash); i++)
            printf("%02x", buf[i]);
        printf("\n");

        memcpy(buf, signature, sizeof(signature));
        if (maid_sign_verify(s, buf) && maid_mem_cmp(buf, hash, 256 / 8))
            printf("Valid!\n");
        else
            printf("Invalid!\n");

        for (size_t i = 0; i < sizeof(hash); i++)
            printf("%02x", buf[i]);
        printf("\n");
    }
    maid_sign_del(s);

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