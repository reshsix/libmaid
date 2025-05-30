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

# Stream ciphers

```c
#include <maid/stream.h>
```

## Internal Interface

<details>
<summary>struct maid_stream_def</summary>
Type that defines a stream cipher algorithm

</details>

## External Interface

<details>
<summary>maid_stream</summary>
Opaque type that contains the state of a stream cipher

</details>

<details>
<summary>maid_stream *maid_stream_new(struct maid_stream_def def,
                                      const u8 *restrict key,
                                      const u8 *restrict nonce,
                                      u64 counter)</summary>
Creates a stream cipher instance

### Parameters
| name    | description          |
|---------|----------------------|
| def     | Algorithm definition |
| key     | Algorithm-dependent  |
| nonce   | Algorithm-dependent  |
| counter | Algorithm-dependent  |

### Return value
| case    | description          |
|---------|----------------------|
| Success | maid_stream instance |
| Failure | NULL                 |

</details>

<details>
<summary>maid_stream *maid_stream_del(maid_stream *st)</summary>
Deletes a stream cipher instance

### Parameters
| name | description          |
|------|----------------------|
| st   | maid_stream instance |

### Return value
| case   | description |
|--------|-------------|
| Always | NULL        |

</details>

<details>
<summary>void maid_stream_renew(maid_stream *st, const u8 *restrict key,
                                const u8 *restrict nonce,
                                u64 counter)</summary>
Recreates a stream cipher instance

### Parameters
| name    | description          |
|---------|----------------------|
| st      | maid_stream instance |
| key     | Algorithm-dependent  |
| nonce   | Algorithm-dependent  |
| counter | Algorithm-dependent  |

</details>

<details>
<summary>void maid_stream_xor(maid_stream *st,
                              u8 *buffer, size_t size)</summary>
Generates keystream, and applies it with a xor operation

### Parameters
| name   | description           |
|--------|-----------------------|
| st     | maid_stream instance  |
| buffer | Memory to be ciphered |
| size   | Size of the operation |

</details>

## External Algorithms

<details>
<summary>const struct maid_stream_def maid_chacha20</summary>
Chacha20 stream cipher (IETF version)

### Parameters
| name    | description  |
|---------|--------------|
| key     | 256-bit key  |
| nonce   | 96-bit nonce |
| counter | 0 to 2^32    |
</details>

## Example Code

```c
#include <stdio.h>
#include <stdlib.h>

#include <maid/mem.h>

#include <maid/stream.h>

int main(void)
{
    u8 key[32] = {0};
    u8 iv [16] = {0};

    maid_stream *st = maid_stream_new(maid_chacha20, key, iv, 0);

    u8 data[64] = {0};
    if (st)
        maid_stream_xor(st, data, sizeof(data));

    maid_stream_del(st);

    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x", data[i]);
    printf("\n");

    maid_mem_clear(key, sizeof(key));

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
