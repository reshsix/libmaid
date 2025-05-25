<div align="center">
    <h3 align="center">A Cryptography Library for Maids</h3>
    <a href="https://github.com/reshsix/libmaid">
        <img src="logo.png" width="96" height="96">
    </a>
</div>

## ☕ About
Version: **1.3 beta**

## 🎬 Getting Started

### Prerequisites
- A C99 compiler

### Build
Files are created in `build`
```sh
make
make test
```

### Installation
Files are installed in `/usr/local`
```sh
sudo make install
sudo ldconfig
```

### Usage
The library can be linked with -lmaid, and a command-line tool `maid` is
available

## 📖 Reference
| Category                             | Algorithms                |
| ------------------------------------:|---------------------------|
| [Type aliases](docs/types.md)        | ------------------------- |
| [Memory utils](docs/mem.md)          | Base64                    |
| [Multiprecision](docs/mp.md)         | ------------------------- |
|                                      |                           |
| [Block ciphers](docs/block.md)       | AES-ECB, AES-CTR          |
| [Stream ciphers](docs/stream.md)     | Chacha20                  |
| [MACs](docs/mac.md)                  | Poly1305, HMAC-SHA2       |
| [AEADs](docs/aead.md)                | AES-GCM, Chacha20Poly1305 |
| [CSPRNGs](docs/rng.md)               | CTR-DRBG-AES              |
| [Hash functions](docs/hash.md)       | SHA-2                     |
|                                      |                           |
| [Public-key primitives](docs/pub.md) | RSA                       |
| [Digital signatures](docs/sign.md)   | PKCS#1 (v1.5)             |
| [Key exchange](docs/kex.md)          | Diffie-Hellman            |
|                                      |                           |
| [Serialization](docs/serial.md)      | PEM, PKCS#1, PKCS#8       |
| [Key generation](docs/keygen.md)     | RSA                       |
