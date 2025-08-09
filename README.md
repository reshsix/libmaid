<div align="center">
    <h1>$${\color{BrickRed}A\ Cryptography\ Library\ for\ Maids}$$</h1>
    <img src="poster.png" width="333">
</div>

$${For\ those\ who\ keep\ the\ ember\ through\ the\ storm}$$
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

### $${\color{GoldenRod}Usage}$$
The library can be linked with -lmaid, and a command-line tool `maid` is
available

## $${\color{BrickRed}Instructions}$$
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
|                                      |                           |
| [Public-key primitives](docs/pub.md) | RSA                       |
| [Digital signatures](docs/sign.md)   | PKCS#1 (v1.5)             |
| [Key exchange](docs/kex.md)          | Diffie-Hellman            |
|                                      |                           |
| [Serialization](docs/serial.md)      | PEM, PKCS#1, PKCS#8       |
| [Key generation](docs/keygen.md)     | RSA                       |
|                                      |                           |
| [Password hashing](docs/pass.md)     | PBKDF2                    |
