# Maid
**Status: 1.4 γ**

## Headers
Generic
- [Memory](include/maid/mem.h),
  [Multiprecision](include/maid/mp.h),
  [Finite field](include/maid/ff.h)
- [Stream](include/maid/stream.h),
  [MAC](include/maid/mac.h),
  [AEAD](include/maid/aead.h),
  [CSPRNG](include/maid/rng.h),
  [Hash](include/maid/hash.h),
  [KDF](include/maid/kdf.h)
- [Elliptic curve](include/maid/ecc.h),
  [Signature](include/maid/sign.h),
  [Key exchange](include/maid/kex.h)

Algorithms
- [Chacha20](include/maid/crypto/chacha20.h),
  [Poly1305](include/maid/crypto/poly1305.h),
  [Chacha20Poly1305](include/maid/crypto/chacha20poly1305.h)
- [Chacha20-RNG](include/maid/crypto/chacha20rng.h),
  [BLAKE2](include/maid/crypto/blake2.h),
  [BLAKE2 (Keyed)](include/maid/crypto/blake2k.h)
- [SHA-2](include/maid/crypto/sha2.h),
  [HMAC SHA-2](include/maid/crypto/hmac_sha2.h),
  [HKDF SHA-2](include/maid/crypto/hkdf_sha2.h)
- [Curve25519](include/maid/crypto/curve25519.h),
  [Edwards25519](include/maid/crypto/edwards25519.h)
- [Ed25519](include/maid/crypto/ed25519.h),
  [X25519](include/maid/crypto/x25519.h)


## Assembling
Built as `libmaid.a`
```sh
make
make test
```
