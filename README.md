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

## Library Reference
| Category       | Algorithms                | Documentation               | Examples                        |
| -------------- |:-------------------------:|:---------------------------:|:-------------------------------:|
| Block ciphers  | AES-ECB, AES-CTR          | [block.md](docs/block.md)   | [block.md](examples/block.md)   |
| Stream ciphers | Chacha20                  | [stream.md](docs/stream.md) | [stream.md](examples/stream.md) |
| MACs           | Poly1305                  | [mac.md](docs/mac.md)       | [mac.md](examples/mac.md)       |
| AEADs          | AES-GCM, Chacha20Poly1305 | [aead.md](docs/aead.md)     | [aead.md](examples/aead.md)     |
