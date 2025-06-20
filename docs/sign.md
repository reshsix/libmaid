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
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha1</summary>
PKCS#1 v1.5 signature with SHA-1 (RSA Security)

### Parameters

#### maid_sign_generate
| name   | description             |
|--------|-------------------------|
| buffer | 160-bits -> [bits]-bits |

#### maid_sign_verify
| name   | description             |
|--------|-------------------------|
| buffer | [bits]-bits -> 160-bits |

</details>

<details>
<summary>const struct maid_sign_def maid_pkcs1_v1_5_sha224</summary>
PKCS#1 v1.5 signature with SHA-224 (RSA Security)

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
PKCS#1 v1.5 signature with SHA-256 (RSA Security)

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
PKCS#1 v1.5 signature with SHA-384 (RSA Security)

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
PKCS#1 v1.5 signature with SHA-512 (RSA Security)

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
PKCS#1 v1.5 signature with SHA-512/224 (RSA Security)

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
PKCS#1 v1.5 signature with SHA-512/256 (RSA Security)

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
#include <maid/serial.h>

#include <maid/sign.h>

static u8 hash[256 / 8] =
    {0x35, 0x5c, 0xd8, 0x22, 0x9d, 0x6d, 0x67, 0xa9, 0xfd, 0x82, 0xff, 0x31,
     0xa7, 0x7d, 0x56, 0x36, 0x83, 0x1a, 0x2f, 0xd8, 0xfc, 0x00, 0x7e, 0x46,
     0x48, 0x74, 0x88, 0xe5, 0x21, 0x3e, 0x5d, 0x7a};

static u8 signature[2048 / 8] =
    {0x2d, 0x43, 0x2e, 0x7d, 0x7a, 0x18, 0x7f, 0x8e, 0x2f, 0x3a, 0xd3, 0x70,
     0x6c, 0xfb, 0x71, 0x1d, 0xf4, 0x7b, 0xa7, 0x77, 0xdb, 0xcb, 0xa7, 0xcc,
     0x3b, 0x9b, 0xc5, 0x01, 0xf0, 0xa5, 0xad, 0x65, 0x09, 0x28, 0xec, 0xb7,
     0x42, 0x2e, 0xbf, 0xc2, 0x74, 0x95, 0x3d, 0xa5, 0xda, 0xd5, 0x8f, 0xac,
     0xc9, 0xcd, 0xe6, 0x58, 0x9f, 0x00, 0xf0, 0x93, 0x60, 0x39, 0xa4, 0x76,
     0x97, 0x27, 0xd9, 0x17, 0x6e, 0xd8, 0x3d, 0xf2, 0x26, 0x68, 0x67, 0x82,
     0xe2, 0x7b, 0x2e, 0xcc, 0x6e, 0x34, 0x78, 0x9b, 0xdb, 0xe8, 0x42, 0xd8,
     0x29, 0xf3, 0x22, 0xf4, 0x96, 0xab, 0xff, 0x3a, 0x4d, 0x4b, 0xb1, 0xcd,
     0x0a, 0xa6, 0xed, 0x3f, 0x58, 0xfd, 0x5c, 0x60, 0xc1, 0x7b, 0xb7, 0xc2,
     0xfb, 0x0c, 0x25, 0x0a, 0x25, 0x30, 0xb0, 0x06, 0xf2, 0x5c, 0x3c, 0x02,
     0xcc, 0x04, 0x04, 0x2b, 0x88, 0xde, 0x79, 0xe1, 0x0c, 0x2f, 0xbc, 0x77,
     0xc7, 0xa3, 0x6b, 0xd9, 0x0c, 0xb0, 0x04, 0x30, 0x06, 0xd4, 0xf7, 0x3b,
     0x36, 0x53, 0x4e, 0x9d, 0x6f, 0x34, 0x5f, 0xba, 0xe1, 0xc5, 0x6b, 0x17,
     0xda, 0xf0, 0x44, 0x23, 0x88, 0x2e, 0x8e, 0x95, 0x64, 0x5e, 0x36, 0xfa,
     0x3b, 0x73, 0xc4, 0xe4, 0x33, 0xd6, 0x00, 0xa4, 0x6d, 0x76, 0xf0, 0x77,
     0x13, 0x43, 0xb1, 0x77, 0x9d, 0xe4, 0x0e, 0x21, 0x68, 0xde, 0x54, 0xe6,
     0xe5, 0xea, 0x68, 0x3b, 0xae, 0xe1, 0x6b, 0xc4, 0x4f, 0x71, 0x95, 0x35,
     0xb9, 0xcb, 0xad, 0x36, 0x7d, 0x47, 0xb6, 0xc5, 0x8f, 0xb6, 0x1f, 0xf0,
     0x1b, 0xc9, 0x65, 0x8e, 0x7f, 0x0e, 0xfe, 0xe0, 0x5b, 0xc3, 0x0a, 0xb1,
     0x76, 0xbb, 0x85, 0xaf, 0x96, 0xba, 0x7d, 0x66, 0xc7, 0x13, 0xa5, 0x2c,
     0x05, 0xdd, 0xdd, 0x0a, 0xd3, 0x6d, 0xf7, 0x98, 0x43, 0x7e, 0xd4, 0x2f,
     0xef, 0x5f, 0xd7, 0x5d};

int main(void)
{
    int ret = EXIT_FAILURE;

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
            struct maid_rsa_key pubkey = {.exponent = params[1],
                                          .modulo   = params[0]};

            maid_pub *pub = maid_pub_new(maid_rsa_public, &pubkey, bits);
            maid_sign *s = maid_sign_new(maid_pkcs1_v1_5_sha256,
                                         pub, NULL, bits);
            if (s)
            {
                u8 buffer[bits / 8];

                memcpy(buffer, signature, sizeof(signature));
                if (maid_sign_verify(s, buffer) &&
                    maid_mem_cmp(buffer, hash, sizeof(hash)))
                    printf("Signature valid!\n");
                else
                    printf("Signature invalid!\n");
            }
            else
                fprintf(stderr, "Out of memory\n");

            maid_sign_del(s);
            maid_pub_del(pub);

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
