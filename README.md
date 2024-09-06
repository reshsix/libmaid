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
| Category       | Algorithms                | Documentation               |
| -------------- |:-------------------------:|:---------------------------:|
| Memory utils   |                           | [mem.md](docs/mem.md)       |
| Block ciphers  | AES-ECB, AES-CTR          | [block.md](docs/block.md)   |
| Stream ciphers | Chacha20                  | [stream.md](docs/stream.md) |
| MACs           | Poly1305                  | [mac.md](docs/mac.md)       |
| AEADs          | AES-GCM, Chacha20Poly1305 | [aead.md](docs/aead.md)     |
| CSPRNGs        | CTR-DRBG-AES              | [rng.md](docs/rng.md)       |
| Hash functions | SHA-2                     | [hash.md](docs/hash.md)     |
