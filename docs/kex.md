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

# Kex exchange algorithms

```c
#include <maid/kex.h>
```

## Internal Interface

<details>
<summary>struct maid_kex_def</summary>
Type that defines a key exchange algorithm

</details>

## External Interface

<details>
<summary>maid_kex</summary>
Opaque type that contains the state of a key exchange algorithm

</details>

<details>
<summary>maid_kex *maid_kex_new(struct maid_kex_def def,
                                const void *cfg, size_t bits)</summary>
Creates a key exchange instance

### Parameters
| name | description          |
|------|----------------------|
| def  | Algorithm definition |
| cfg  | Algorithm-dependent  |
| bits | Algorithm-dependent  |

### Return value
| case    | description       |
|---------|-------------------|
| Success | maid_kex instance |
| Failure | NULL              |

</details>

<details>
<summary>maid_kex *maid_kex_del(maid_kex *x)</summary>
Deletes a key exchange instance

### Parameters
| name | description       |
|------|-------------------|
| x    | maid_kex instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_kex_renew(maid_kex *x, const void *cfg)</summary>
Recreates a key exchange instance

### Parameters
| name | description         |
|------|---------------------|
| x    | maid_kex instance   |
| cfg  | Algorithm-dependent |

</details>

<details>
<summary>void maid_kex_gpub(maid_kex *x, const void *private,
                            void *public)</summary>
Generates public key for key exchange

### Parameters
| name    | description               |
|---------|---------------------------|
| x       | maid_kex instance         |
| private | Local private key         |
| public  | Local public key (output) |

</details>

<details>
<summary>void maid_kex_gsec(maid_kex *x, const void *private,
                            const void *public, u8 *buffer)</summary>
Generates secret from key exchange

### Parameters
| name    | description         |
|---------|---------------------|
| x       | maid_kex instance   |
| private | Local private key   |
| public  | External public key |
| buffer  | Secret output       |

</details>

## External Algorithms

<details>
<summary>struct maid_dh_group</summary>
Diffie-Hellman group

### Parameters

| name      | description         |
|-----------|---------------------|
| generator | Generator (base)    |
| modulo    | Modulo (safe prime) |

</details>

<details>
<summary>const struct maid_kex_def maid_dh</summary>
Diffie-Hellman key exchange (IETF)

### Parameters

#### maid_kex_new
| name | description                       |
|------|-----------------------------------|
| cfg  | struct maid_dh_group *            |
| bits | Multiple of maid_mp_word bit size |

#### maid_kex_gpub
| name    | description             |
|---------|-------------------------|
| private | bits sized (big-endian) |
| public  | bits sized (big-endian) |

#### maid_kex_gsec
| name    | description             |
|---------|-------------------------|
| private | bits sized (big-endian) |
| public  | bits sized (big-endian) |
| secret  | bits sized (big-endian) |

</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>
#include <maid/hash.h>

#include <maid/kex.h>

static u8 modulo[2048 / 8] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
     0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
     0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
     0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
     0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
     0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
     0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
     0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
     0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
     0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
     0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
     0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
     0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
     0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
     0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
     0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
     0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
     0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
     0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
     0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
     0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xac, 0xaa, 0x68, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff};

static void
gprv(u8 *data, size_t length)
{
    /* Get a static private key, or ephemeral random bytes,
     * using a properly initialized CSPRNG like CTR-DRBG */
    for (int i = 0; i < length; i++)
        data[i] = i;
}

static void
send(u8 *data, size_t length)
{
    /* Send data to Bob */
    (void)data, (void)length;
}

static void
recv(u8 *data, size_t length)
{
    /* Receive data from Bob */
    for (int i = 0; i < length; i++)
        data[i] = length - i - 1;
}

int main(void)
{
    /* 2048-bit MODP group (14) */

    size_t bits = 2048;
    size_t words = maid_mp_words(bits);
    size_t bytes = bits / 8;

    maid_mp_word g[words];
    maid_mp_word p[words];

    maid_mp_mov(words, g, NULL);
    maid_mp_mov(words, p, NULL);

    g[0] = 2;
    maid_mp_read(words, p, modulo, true);

    struct maid_dh_group group = {.generator = g, .modulo = p};

    maid_kex *x = maid_kex_new(maid_dh, &group, bits);
    if (x)
    {
        u8 prv[bytes];
        gprv(prv, sizeof(prv));

        u8 pub[bytes];
        maid_kex_gpub(x, prv, pub);
        send(pub, sizeof(pub));

        u8 pub2[bytes];
        recv(pub2, sizeof(pub2));

        u8 secret[bytes];
        maid_kex_gsec(x, prv, pub2, secret);

        maid_hash *h = maid_hash_new(maid_sha256);
        if (h)
        {
            u8 hash[256 / 8] = {0};
            maid_hash_update(h, secret, sizeof(secret));
            maid_hash_digest(h, hash);

            printf("Shared secret: ");
            for (size_t i = 0; i < sizeof(hash); i++)
                printf("%02x", hash[i]);
            printf("\n");

            maid_mem_clear(hash, sizeof(hash));
        }
        maid_hash_del(h);

        maid_mem_clear(prv,    sizeof(prv));
        maid_mem_clear(secret, sizeof(secret));
    }
    maid_kex_del(x);
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
