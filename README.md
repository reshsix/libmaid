# libmaid
A Cryptography Library for Maids

## Compilation
Files are created in `build`, and can be installed with `make install`
```sh
make
make test
```

## Development status
Currently: **1.0 pre-release**

### Implemented algorithms
| Category       | Algorithms                |
| -------------- |:-------------------------:|
| Block ciphers  | AES (128, 192, 256)       |
| Block modes    | ECB, CTR                  |
| Stream ciphers | Chacha20                  |
| MACs           | Poly1305                  |
| AEADs          | AES-GCM, Chacha20Poly1305 |

### Planned for the next version
| Category  | Algorithms |
| --------- |:----------:|
| Hashes    | SHA-2      |
| CSPRNG    | CTR-DRBG   |
