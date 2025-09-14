
# nim_chacha20_poly1305

![Security Tests](https://github.com/lantos1618/nim_chacha20_poly1305/actions/workflows/security-tests.yml/badge.svg)
[![Security Status](https://img.shields.io/badge/Security-HARDENED-brightgreen)](https://github.com/lantos1618/nim_chacha20_poly1305)
[![Dependencies](https://img.shields.io/badge/Dependencies-ZERO-blue)](https://github.com/lantos1618/nim_chacha20_poly1305)

A **security-hardened** pure Nim library implementing:
- ChaCha20 stream cipher
- Poly1305 message authentication  
- ChaCha20-Poly1305 AEAD
- XChaCha20-Poly1305 extended AEAD


## 🔒 SECURITY-HARDENED IMPLEMENTATION ✅

**This implementation has been thoroughly security-reviewed and hardened:**

- ✅ **Constant-time operations** - Eliminates timing side-channel attacks
- ✅ **Zero external dependencies** - Fully self-contained, auditable codebase  
- ✅ **Comprehensive bounds checking** - Prevents buffer overflows
- ✅ **Input validation** - Guards against malformed data attacks
- ✅ **Secure memory handling** - Prevents sensitive data leakage
- ✅ **Constant-time MAC verification** - Protects against timing attacks on authentication
- ✅ **Memory clearing** - Securely erases sensitive key material

### TODO
- [x] chacha20
	- [x] quarter round
	- [x] quarter rounds
	- [x] inner block
	- [x] add block
	- [x] serialize block
	- [x] chacha20_init
	- [x] chacha_xor
- [x] poly1305
	- [x] poly_pad
	- [x] poly_init
	- [x] poly_update
	- [x] poly_finalize - **SECURITY: Implemented with secure memory clearing**
- [x] chacha20_poly1305
	- [x] chacha20_poly1305_encrypt
	- [x] chacha20_poly1305_decrypt
	- [x] chacha20_poly1305_verify - **SECURITY: Constant-time verification**
- [x] xchacha20_poly1305
	- [x] hchacha20_init
	- [x] hchacha20
- [x] streams - **SECURITY: Full streaming cipher with proper state management ✅**
- [ ] factory that gives chacha(n) rounds  
- [ ] add more test vectors
- [x] make style more uniform - **SECURITY: Added comprehensive security documentation**
- [x] add helpers byte[] <-> string <-> hex[] - **SECURITY: Safe conversion functions with validation**
- [ ] add runable examples?

### Resources & References

chacha20
- https://datatracker.ietf.org/doc/html/rfc7539
  
note xchacha, as of 2022 still in draft
- https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
- https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt
  
another chacha20 implementation:
- https://git.sr.ht/~ehmry/chacha20


## Usage
```nim
import  nim_chacha20_poly1305/[common, chacha20, poly1305, xchacha20_poly1305]

export common
export chacha20
export poly1305
export xchacha20_poly1305

import std/sysrand

proc main() =
    var
        key_in: Key = [
            0x80'u8, 0x81'u8, 0x82'u8, 0x83'u8, 0x84'u8, 0x85'u8, 0x86'u8, 0x87'u8, 0x88'u8, 0x89'u8, 0x8a'u8, 0x8b'u8, 0x8c'u8, 0x8d'u8, 0x8e'u8, 0x8f'u8,
            0x90'u8, 0x91'u8, 0x92'u8, 0x93'u8, 0x94'u8, 0x95'u8, 0x96'u8, 0x97'u8, 0x98'u8, 0x99'u8, 0x9a'u8, 0x9b'u8, 0x9c'u8, 0x9d'u8, 0x9e'u8, 0x9f'u8,
        ]
        nonce_in: XNonce
        encrypt_counter: Counter
        decrypt_counter: Counter
        # Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
        plain_data: array[114, byte] = [
            0x4c'u8, 0x61'u8, 0x64'u8, 0x69'u8, 0x65'u8, 0x73'u8, 0x20'u8, 0x61'u8, 0x6e'u8, 0x64'u8, 0x20'u8, 0x47'u8, 0x65'u8, 0x6e'u8, 0x74'u8, 0x6c'u8,
            0x65'u8, 0x6d'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x63'u8, 0x6c'u8, 0x61'u8, 0x73'u8,
            0x73'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x20'u8, 0x27'u8, 0x39'u8, 0x39'u8, 0x3a'u8, 0x20'u8, 0x49'u8, 0x66'u8, 0x20'u8, 0x49'u8, 0x20'u8, 0x63'u8,
            0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x6f'u8, 0x66'u8, 0x66'u8, 0x65'u8, 0x72'u8, 0x20'u8, 0x79'u8, 0x6f'u8, 0x75'u8, 0x20'u8, 0x6f'u8,
            0x6e'u8, 0x6c'u8, 0x79'u8, 0x20'u8, 0x6f'u8, 0x6e'u8, 0x65'u8, 0x20'u8, 0x74'u8, 0x69'u8, 0x70'u8, 0x20'u8, 0x66'u8, 0x6f'u8, 0x72'u8, 0x20'u8,
            0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x66'u8, 0x75'u8, 0x74'u8, 0x75'u8, 0x72'u8, 0x65'u8, 0x2c'u8, 0x20'u8, 0x73'u8, 0x75'u8, 0x6e'u8, 0x73'u8,
            0x63'u8, 0x72'u8, 0x65'u8, 0x65'u8, 0x6e'u8, 0x20'u8, 0x77'u8, 0x6f'u8, 0x75'u8, 0x6c'u8, 0x64'u8, 0x20'u8, 0x62'u8, 0x65'u8, 0x20'u8, 0x69'u8,
            0x74'u8, 0x2e'u8
        ]   
        auth_data_in = [
            0x50'u8, 0x51'u8, 0x52'u8, 0x53'u8, 0xc0'u8, 0xc1'u8, 0xc2'u8, 0xc3'u8, 0xc4'u8, 0xc5'u8, 0xc6'u8, 0xc7'u8,
        ]
        cipher_data_decrypted: array[114, byte]
        tag_out: Tag
        tag_expected: Tag 
        cipher_data_expected: array[114, byte]

    encrypt_counter = decrypt_counter
    discard urandom(nonce_in)
    xchacha20_aead_poly1305_encrypt(
        key_in,
        nonce_in,
        encrypt_counter,
        auth_data_in,
        plain_data,
        cipher_data_expected,
        tag_expected
    )

    xchacha20_aead_poly1305_decrypt(
        key_in,
        nonce_in,
        decrypt_counter,
        auth_data_in,
        cipher_data_decrypted,
        cipher_data_expected,
        tag_out
    )
    if tag_out != tag_expected:
        echo "MESSAGE IS POISONED"
    
    echo $$$cipher_data_decrypted

when isMainModule:
    main()
```
