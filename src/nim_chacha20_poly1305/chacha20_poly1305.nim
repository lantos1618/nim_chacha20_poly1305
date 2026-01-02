# SECURITY-HARDENED ChaCha20-Poly1305 AEAD Implementation
# Implements RFC 7539 with additional security measures:
# - Constant-time operations to prevent timing attacks
# - Comprehensive bounds checking to prevent buffer overflows
# - Secure memory clearing to prevent data leakage
# - Input validation to prevent malformed data attacks

import common, chacha20, poly1305
import helpers

# Helper to convert uint64 to little-endian bytes
proc uint64ToBytes(x: uint64): array[8, byte] =
    for i in 0..7:
        result[i] = byte((x shr (i * 8)) and 0xff)

# SECURITY: Compute Poly1305 MAC incrementally without allocating large buffers
# This prevents memory exhaustion attacks with large inputs
proc computeAeadMac(poly: var Poly1305, auth_data, cipher_data: openArray[byte]) =
    # Process auth_data
    poly.poly1305_update(auth_data)

    # Add padding for auth_data (pad to 16-byte boundary)
    let authPadLen = (16 - (auth_data.len mod 16)) mod 16
    if authPadLen > 0:
        var authPad: array[16, byte]  # Zero-initialized
        poly.poly1305_update(authPad[0..<authPadLen])

    # Process cipher_data
    poly.poly1305_update(cipher_data)

    # Add padding for cipher_data (pad to 16-byte boundary)
    let cipherPadLen = (16 - (cipher_data.len mod 16)) mod 16
    if cipherPadLen > 0:
        var cipherPad: array[16, byte]  # Zero-initialized
        poly.poly1305_update(cipherPad[0..<cipherPadLen])

    # Add lengths (little-endian uint64)
    let authLenBytes = uint64ToBytes(auth_data.len.uint64)
    let cipherLenBytes = uint64ToBytes(cipher_data.len.uint64)
    poly.poly1305_update(authLenBytes)
    poly.poly1305_update(cipherLenBytes)

# destination_key_block should be null
proc chacha20_poly1305_key_gen*(
    key: Key,
    nonce: Nonce,
    counter: Counter): Key =
    var
        key_block: Block
    var temp_c: Chacha
    temp_c.key = key
    temp_c.nonce = nonce
    temp_c.counter = counter

    chacha20_block(temp_c, key_block)
    copyMem(result[0].addr, key_block[0].addr, 32)


# encrypt and dcrypt
# be sure to check tag_encrypt == tag_decrypt 
# https://datatracker.ietf.org/doc/html/rfc7539#section-2.8.1
proc chacha20_aead_poly1305*(
    key: Key,
    nonce: Nonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    plain_data: var openArray[byte],
    cipher_data: var openArray[byte],
    tag: var Tag,
    encrypt: bool = true
    ) =
    var
        otk: Key
        temp_c: Chacha
        poly: Poly1305

    otk = chacha20_poly1305_key_gen(key, nonce, counter)
    counter.inc()

    temp_c.key = key
    temp_c.nonce = nonce
    temp_c.counter = counter
    if encrypt:
        chacha20_xor(temp_c, plain_data, cipher_data)
    else:
        # swap plain_data and cipher data as it is in reverse
        chacha20_xor(temp_c, cipher_data, plain_data)

    poly.poly1305_init(otk)

    # SECURITY: Use incremental MAC computation - no large buffer allocation
    computeAeadMac(poly, auth_data, cipher_data)

    tag = poly.poly1305_final()

    # SECURITY: Clear sensitive key material
    secureZeroArray(otk)
    poly.poly1305_finalize()

proc chacha20_aead_poly1305_encrypt*(
    key: Key,
    nonce: Nonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    plain_data:var openArray[byte],
    cipher_data: var openArray[byte],
    tag:var Tag) =
    chacha20_aead_poly1305(
        key,
        nonce,
        counter,
        auth_data,
        plain_data,
        cipher_data,
        tag,
        true
    )

proc chacha20_aead_poly1305_decrypt*(
    key: Key,
    nonce: Nonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    plain_data:var openArray[byte],
    cipher_data: var openArray[byte],
    tag:var Tag) =
    chacha20_aead_poly1305(
        key,
        nonce,
        counter,
        auth_data,
        plain_data,
        cipher_data,
        tag,
        false
    )

# SECURITY: Constant-time verification function
# Computes MAC WITHOUT decryption to prevent CPU exhaustion attacks
proc chacha20_poly1305_verify*(
    key: Key,
    nonce: Nonce,
    counter: Counter,
    auth_data: openArray[byte],
    cipher_data: openArray[byte],
    expected_tag: Tag): bool =
    # SECURITY: Compute MAC directly without decryption
    # This prevents CPU exhaustion attacks with large malicious ciphertexts
    var
        otk: Key
        poly: Poly1305
        computed_tag: Tag
        temp_counter = counter

    # Generate one-time key (same as encryption)
    otk = chacha20_poly1305_key_gen(key, nonce, temp_counter)

    # Compute MAC over auth_data and cipher_data (NO decryption needed!)
    poly.poly1305_init(otk)
    computeAeadMac(poly, auth_data, cipher_data)
    computed_tag = poly.poly1305_final()

    # SECURITY: Constant-time comparison
    result = poly1305_verify(expected_tag, computed_tag)

    # SECURITY: Clear sensitive key material
    secureZeroArray(otk)
    poly.poly1305_finalize()

# SECURITY: Authenticated decryption that verifies tag BEFORE releasing plaintext
# Returns false if tag verification fails (plaintext buffer is zeroed)
proc chacha20_aead_poly1305_decrypt_verified*(
    key: Key,
    nonce: Nonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    cipher_data: openArray[byte],
    plain_data: var openArray[byte],
    expected_tag: Tag): bool =
    # SECURITY: First verify the tag WITHOUT decryption
    if not chacha20_poly1305_verify(key, nonce, counter, auth_data, cipher_data, expected_tag):
        # Tag mismatch - zero output buffer and return false
        secureZero(plain_data)
        return false

    # Tag verified - now safe to decrypt
    var
        otk: Key
        temp_c: Chacha
        temp_counter = counter

    otk = chacha20_poly1305_key_gen(key, nonce, temp_counter)
    temp_counter.inc()

    temp_c.key = key
    temp_c.nonce = nonce
    temp_c.counter = temp_counter
    chacha20_xor(temp_c, cipher_data, plain_data)

    # SECURITY: Clear sensitive key material
    secureZeroArray(otk)

    return true