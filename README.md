# ChaCha20-Poly1305 Cryptographic Library for Nim

![Tests](https://github.com/lantos1618/nim_chacha20_poly1305/actions/workflows/security-tests.yml/badge.svg)

A pure Nim implementation of ChaCha20-Poly1305 AEAD encryption:

- **ChaCha20** - Stream cipher (RFC 7539)
- **Poly1305** - Message authentication code
- **ChaCha20-Poly1305** - Authenticated encryption (AEAD)
- **XChaCha20-Poly1305** - Extended nonce variant
- **Streaming API** - For processing large data

## Installation

```bash
nimble install https://github.com/lantos1618/nim_chacha20_poly1305
```

**Requirements**: Nim >= 1.6.0 | Zero external dependencies

---

## Quick Start

### Basic Encryption/Decryption

```nim
import nim_chacha20_poly1305/[common, chacha20_poly1305]
import std/sysrand

var key: Key
var nonce: Nonce
discard urandom(key)
discard urandom(nonce)

var plaintext = cast[seq[byte]]("Secret message!")
let auth_data = cast[seq[byte]]("Public metadata")

# Encrypt
var ciphertext = newSeq[byte](plaintext.len)
var tag: Tag
var counter: Counter = 0

chacha20_aead_poly1305_encrypt(
    key, nonce, counter,
    auth_data, plaintext, ciphertext, tag
)

# Decrypt (always use the verified function)
var decrypted = newSeq[byte](ciphertext.len)
counter = 0

let success = chacha20_aead_poly1305_decrypt_verified(
    key, nonce, counter,
    auth_data, ciphertext, decrypted, tag
)

if success:
    echo "Decrypted: ", cast[string](decrypted)
else:
    echo "Authentication failed!"
    # decrypted buffer is automatically zeroed on failure
```

### XChaCha20-Poly1305 (Extended Nonce)

```nim
import nim_chacha20_poly1305/[common, xchacha20_poly1305]

var key: Key
var xnonce: XNonce  # 24 bytes instead of 12
discard urandom(key)
discard urandom(xnonce)

let message = cast[seq[byte]]("Extended nonce encryption!")
let auth_data = cast[seq[byte]]("Additional data")

var ciphertext = newSeq[byte](message.len)
var tag: Tag
var counter: Counter = 0

xchacha20_aead_poly1305_encrypt(
    key, xnonce, counter,
    auth_data, message, ciphertext, tag
)
```

---

## Streaming API

> **Warning**: Streaming decryption releases plaintext before tag verification. For untrusted data, use `streamDecrypt()` which buffers and verifies first, or implement chunked authentication.

### One-Shot Functions (Recommended)

```nim
import nim_chacha20_poly1305/[common, streaming]

var key: Key
var nonce: Nonce
discard urandom(key)
discard urandom(nonce)

let auth_data = cast[seq[byte]]("Authenticated data")
let plaintext = cast[seq[byte]]("Message to encrypt")

# Encrypt
var ciphertext = newSeq[byte](plaintext.len)
let tag = streamEncrypt(key, nonce, auth_data, plaintext, ciphertext)

# Decrypt with verification
var decrypted = newSeq[byte](ciphertext.len)
let success = streamDecrypt(key, nonce, auth_data, ciphertext, decrypted, tag)
```

### Streaming Cipher (ChaCha20)

```nim
var cipher = initStreamCipher(key, nonce, counter = 0)

var encrypted = newSeq[byte](chunk.len)
cipher.update(chunk, encrypted)
```

### Streaming AEAD

```nim
# Encryption
var aead = initStreamAEADEncrypt(key, nonce)
aead.updateAuthData(auth_data)
aead.finalizeAuthData()
aead.updateCipherData(plaintext, ciphertext)
let tag = aead.finalize()
```

---

## Utility Functions

```nim
import nim_chacha20_poly1305/helpers

let bytes = hexToBytes("48656c6c6f")
let hex = bytesToHex(bytes)

# Constant-time comparison
let equal = constantTimeEquals(data1, data2)

# Secure memory clearing
secureZero(sensitive_data)
```

---

## API Reference

### Types

```nim
type
    Key* = array[32, byte]      # 256-bit key
    Nonce* = array[12, byte]    # 96-bit nonce
    XNonce* = array[24, byte]   # 192-bit extended nonce
    Tag* = array[16, byte]      # 128-bit auth tag
    Counter* = uint32
```

### ChaCha20-Poly1305

```nim
proc chacha20_aead_poly1305_encrypt*(
    key: Key, nonce: Nonce, counter: var Counter,
    auth_data, plain_data: openArray[byte],
    cipher_data: var openArray[byte], tag: var Tag)

proc chacha20_aead_poly1305_decrypt_verified*(
    key: Key, nonce: Nonce, counter: var Counter,
    auth_data, cipher_data: openArray[byte],
    plain_data: var openArray[byte], expected_tag: Tag): bool

proc chacha20_poly1305_verify*(
    key: Key, nonce: Nonce, counter: Counter,
    auth_data, cipher_data: openArray[byte],
    expected_tag: Tag): bool
```

### Streaming

```nim
proc initStreamCipher*(key: Key, nonce: Nonce, counter: Counter = 0): StreamCipher
proc update*(cipher: var StreamCipher, input, output: openArray[byte])

proc initStreamAEADEncrypt*(key: Key, nonce: Nonce, counter: Counter = 0): StreamAEAD
proc updateAuthData*(aead: var StreamAEAD, auth_data: openArray[byte])
proc finalizeAuthData*(aead: var StreamAEAD)
proc finalize*(aead: var StreamAEAD): Tag
proc verify*(aead: var StreamAEAD, expected_tag: Tag): bool

proc streamEncrypt*(key, nonce, auth_data, plaintext, ciphertext, counter): Tag
proc streamDecrypt*(key, nonce, auth_data, ciphertext, plaintext, tag, counter): bool
```

---

## Development

```bash
# Build
nim c src/nim_chacha20_poly1305.nim
nim c -d:release --opt:speed src/nim_chacha20_poly1305.nim

# Test
nim c -r tests/test_chacha20.nim
nim c -r tests/test_poly1305.nim
nim c -r tests/test_chacha20_poly1305.nim
nim c -r tests/test_xchacha20_poly1305.nim
nim c -r tests/test_streaming_basic.nim
nim c -r tests/test_security_hardened.nim
```

---

## Security Notes

- **Nonces must be unique** per key - use cryptographic RNG
- **Always verify tags** before using decrypted data
- **Use `_decrypt_verified`** functions, not raw decrypt
- **Key management** is your responsibility
- Constant-time operations are used for sensitive comparisons
- Sensitive data is cleared from memory after use

This implementation aims to follow best practices but **has not been independently audited**. Use at your own risk for security-critical applications.

---

## References

- [RFC 7539 - ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc7539)
- [XChaCha20-Poly1305 Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)

## License

MIT
