<div align="center">
    <h1>A Cryptography Library for Maids</h1>
    <img src="poster.png" width="350">
</div>

## Status
Version: 1.4 alpha

| Category                     | Algorithms                   |
| -----------------------------|------------------------------|
| Encoding schemes             | Base16, Base32, Base64       |
| Stream ciphers               | Chacha20                     |
| Message authentication codes | Poly1305, HMAC, BLAKE2       |
| AEAD structures              | Chacha20Poly1305             |
| Random number generators     | Chacha20-RNG                 |
| Hash functions               | SHA-1, SHA-2, BLAKE2         |
| Key derivation functions     | HKDF, PBKDF2                 |
| Digital signatures           | Ed25519                      |
| Key-exchange methods         | Diffie-Hellman               |

### Warnings
- Elliptic curves are currently implemented without a cswap, so they might be
vulnerable to branch-prediction attacks

## Instructions
### Requirements
A `C99` compiler

### Build
Files are created in `build`
```sh
make
build/maid test
```

### Installation
Files are placed in `/usr/local`
```sh
sudo make install
sudo ldconfig
```

### Usage
The library can be linked with -lmaid, and a command-line tool `maid` is
available

| Reference                           |
|:------------------------------------|
| [Type aliases](docs/types.md)       |
| [Memory utils](docs/mem.md)         |
| [Multiprecision](docs/mp.md)        |
|                                     |
| [Stream ciphers](docs/stream.md)    |
| [MACs](docs/mac.md)                 |
| [AEADs](docs/aead.md)               |
| [CSPRNGs](docs/rng.md)              |
| [Hash functions](docs/hash.md)      |
| [Key derivation](docs/kdf.md)       |
|                                     |
| [Elliptic curves](docs/ecc.md)      |
| [Digital signatures](docs/sign.md)  |
| [Key exchange](docs/kex.md)         |
