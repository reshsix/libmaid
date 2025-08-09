# Evil Maid of Babylon
> "And the woman was dressed in purple and scarlet...
having a golden cup full of abominations"

## 🏛️ Overview
Version: **1.4 alpha**

This is a cryptography library for those who are not afraid to live

Written from scratch by a single person,
it embodies the spirit of rolling your own cryptography

There's no certifications, money going to corporations,
or experts bribed in the process of making it

## 🔥 Ritual

### Requirements
- A C99 compiler

### Forging the Seal
Files are forged in `build`
```sh
make
build/maid test
```

### Binding the System
Files are placed in `/usr/local`
```sh
sudo make install
sudo ldconfig
```

### Wielding
The library can be wielded with -lmaid, and a command-line tool `maid` is
available

## 📜 The Codex
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
