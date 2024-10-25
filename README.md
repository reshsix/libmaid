<div align="center">
    <h3 align="center">A Cryptography Library for Maids</h3>
    <a href="https://github.com/reshsix/libmaid">
        <img src="logo.png" width="100" height="100">
    </a>
</div>

## ☕ About
Version: **1.1 alpha**

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

## 📖 Library Reference
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
| [Key Exchange](docs/kex.md)          | Diffie-Hellman            |
