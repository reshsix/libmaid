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
#include <stdio.h>
#include <stdlib.h>

#include <maid/aead.h>

int main(void)
{
    u8 key[32] = {0};
    u8  iv[12] = {0};

    /* Encryption */

    maid_aead *ae = maid_aead_new(maid_aes_gcm_256, key, iv);

    u8   ad[32] = {0};
    u8 data[64] = {0};
    u8  tag[16] = {0};
    if (ae)
    {
        maid_aead_update(ae, ad, sizeof(ad));
        maid_aead_crypt(ae, data, sizeof(data), false);
        maid_aead_digest(ae, tag);
    }

    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x", data[i]);
    printf("\n");

    for (size_t i = 0; i < sizeof(tag); i++)
        printf("%02x", tag[i]);
    printf("\n");

    /* Decryption */

    maid_aead_renew(ae, key, iv);

    u8 tag2[16] = {0};
    if (ae)
    {
        maid_aead_update(ae, ad, sizeof(ad));
        maid_aead_crypt(ae, data, sizeof(data), true);
        maid_aead_digest(ae, tag2);
    }

    maid_aead_del(ae);

    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x", data[i]);
    printf("\n");

    for (size_t i = 0; i < sizeof(tag2); i++)
        printf("%02x", tag2[i]);
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
