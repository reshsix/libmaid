<div align="center">
    <h1>$${\color{BrickRed}A\ Cryptography\ Library\ for\ Maids}$$</h1>
    <img src="poster.png" width="333">
</div>

$${Version:\ 1.4\ alpha}$$

## $${\color{BrickRed}Instructions}$$
### $${\color{GoldenRod}Requirements}$$
$${A}$$ `C99` $${compiler}$$

### $${\color{GoldenRod}Build}$$
$${Files\ are\ created\ in}$$ `build`
```sh
make
build/maid test
```

### $${\color{GoldenRod}Installation}$$
$${Files\ are\ placed\ in}$$ `/usr/local`
```sh
sudo make install
sudo ldconfig
```

### $${\color{GoldenRod}Warnings}$$
- AES is currently implemented using LUT, so it might be
vulnerable to cache-timing attacks
- RSA and ECC are currently implemented without a cswap, so they might be
vulnerable to branch-prediction attacks

### $${\color{GoldenRod}Usage}$$
The library can be linked with -lmaid, and a command-line tool `maid` is
available

## $${\color{BrickRed}Reference}$$
| Category                             | Algorithms                |
| ------------------------------------:|---------------------------|
| [Type aliases](docs/types.md)        | ------------------------- |
| [Memory utils](docs/mem.md)          | Base16, Base32, Base64    |
| [Multiprecision](docs/mp.md)         | ------------------------- |
|                                      |                           |
| [Block ciphers](docs/block.md)       | AES-ECB, AES-CTR          |
| [Stream ciphers](docs/stream.md)     | Chacha20                  |
| [MACs](docs/mac.md)                  | Poly1305, HMAC, BLAKE2    |
| [AEADs](docs/aead.md)                | AES-GCM, Chacha20Poly1305 |
| [CSPRNGs](docs/rng.md)               | CTR-DRBG-AES              |
| [Hash functions](docs/hash.md)       | SHA-1, SHA-2, BLAKE2      |
| [Password hashing](docs/pass.md)     | PBKDF2                    |
|                                      |                           |
| [RSA algorithm](docs/rsa.md)         | PKCS#1 (v1.5)             |
| [Elliptic curves](docs/ecc.md)       | Edwards25519              |
| [PEM format](docs/pem.md)            | PEM                       |
| [ASN1 format](docs/asn1.md)          | ASN.1                     |
| [SPKI structure](docs/spki.md)       | SPKI                      |
| [PKCS8 structure](docs/pkcs8.md)     | PKCS#8                    |
| [Digital signatures](docs/sign.md)   | RSA PKCS#1 (v1.5)         |
| [Key exchange](docs/kex.md)          | Diffie-Hellman            |
