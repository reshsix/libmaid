<div align="center">
    <h1>A Cryptography Library for Maids</h1>
    <img src="poster.png" width="350">
</div>

## Status
Version: 1.4 alpha

| Category                     | Algorithms                 |
| -----------------------------|----------------------------|
| Encoding schemes             | Base16, Base32, Base64     |
| Block ciphers                | AES                        |
| Block cipher modes           | EBC, CTR                   |
| Stream ciphers               | Chacha20                   |
| Message authentication codes | Poly1305, HMAC, BLAKE2     |
| AEAD structures              | AES-GCM, Chacha20Poly1305  |
| Random number generators     | CTR-DRBG-AES               |
| Hash functions               | SHA-1, SHA-2, BLAKE2       |
| Key derivation functions     | HKDF, PBKDF2               |
|                              |                            |
| Asymmetric primitives        | RSA, ECC                   |
| Elliptic curves              | Curve25519, Edwards25519   |
| Public-key encodings         | PEM, DER                   |
| Public key structures        | PKCS#1, SPKI, PKCS#8       |
| Digital signatures           | RSA-PKCS#1 (v1.5), Ed25519 |
| Key-exchange methods         | Diffie-Hellman             |

### Warnings
- AES is currently implemented using LUT, so it might be
vulnerable to cache-timing attacks
- RSA and ECC are currently implemented without a cswap, so they might be
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

## Reference
| General                             | Symmetric                           | Asymmetric                          |
|:------------------------------------|:------------------------------------|:------------------------------------|
| [Type aliases](docs/types.md)       | [Block ciphers](docs/block.md)      | [RSA algorithm](docs/rsa.md)        |
| [Memory utils](docs/mem.md)         | [Stream ciphers](docs/stream.md)    | [Elliptic curves](docs/ecc.md)      |
| [Multiprecision](docs/mp.md)        | [MACs](docs/mac.md)                 | [PEM format](docs/pem.md)           |
|                                     | [AEADs](docs/aead.md)               | [ASN1 format](docs/asn1.md)         |
|                                     | [CSPRNGs](docs/rng.md)              | [SPKI structure](docs/spki.md)      |
|                                     | [Hash functions](docs/hash.md)      | [PKCS#8 structure](docs/pkcs8.md)   |
|                                     | [Key derivation](docs/kdf.md)       | [Digital signatures](docs/sign.md)  |
|                                     |                                     | [Key exchange](docs/kex.md)         |
