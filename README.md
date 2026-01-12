<div align="center">
    <h1>MAID</h1>
    <img src="poster.png" width="350">
    <h3>1.4 Pre-Release</h3>
</div>

## Installation

Created in `build`
```sh
make
build/maid test
```

Placed in `/usr/local`
```sh
sudo make install
sudo ldconfig
```

## Reference

Called by `maid`, linked with -lmaid
| Category                            | Algorithms                   |
|:------------------------------------|:-----------------------------|
| [Memory utils](docs/mem.md)         | Base16, Base32, Base64       |
| [Multiprecision](docs/mp.md)        | R/W, Logic, Arithmetic, Swap |
| [Finite fields](docs/ff.md)         | 1305, 25519, Order25519      |
|                                     |                              |
| [Stream ciphers](docs/stream.md)    | Chacha20                     |
| [MACs](docs/mac.md)                 | Poly1305, HMAC, Blake2       |
| [AEADs](docs/aead.md)               | Chacha20Poly1305             |
| [CSPRNGs](docs/rng.md)              | Chacha20-RNG                 |
| [Hash functions](docs/hash.md)      | SHA-2, BLAKE2                |
| [Key derivation](docs/kdf.md)       | HKDF                         |
|                                     |                              |
| [Elliptic curves](docs/ecc.md)      | Curve25519, Edwards25519     |
| [Digital signatures](docs/sign.md)  | Ed25519                      |
| [Key exchange](docs/kex.md)         | X25519                       |

