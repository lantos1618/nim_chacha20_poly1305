# SECURITY-HARDENED XChaCha20-Poly1305 Implementation
# NOTICE: XChaCha20 is based on draft-irtf-cfrg-xchacha-03 (not final RFC)
# https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-01.html
# https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-03.html
# https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt

import common, chacha20_poly1305, chacha20, helpers

type
    # extended key nonce
    XKN* = object
        sub_key*: Key
        sub_nonce*: Nonce
    XNonce* = array[24, byte]
    XKNonce* = array[16, byte]

proc hchacha20*(key: Key, xnonce: XKNonce): Key  =
    # SECURITY: Validate input lengths
    if key.len != 32:
        raise newException(ValueError, "SECURITY: Key must be exactly 32 bytes")
    if xnonce.len != 16:
        raise newException(ValueError, "SECURITY: XKNonce must be exactly 16 bytes")
    
    var t_state: State
    t_state[0] = 0x61707865'u32
    t_state[1] = 0x3320646e'u32
    t_state[2] = 0x79622d32'u32
    t_state[3] = 0x6b206574'u32
    
    # SECURITY: Safe memory copy with explicit size validation
    static: assert(sizeof(State) >= 16 * sizeof(uint32))
    static: assert(sizeof(Key) == 32)
    static: assert(sizeof(XKNonce) == 16)
    
    copyMem(t_state[4].addr, key[0].unsafeAddr, 32)
    copyMem(t_state[12].addr, xnonce[0].unsafeAddr, 16)
    t_state.chachca20_rounds()

    # SECURITY: Safe result construction with bounds checking
    static: assert(sizeof(Key) == 32)
    copyMem(result[0].addr, t_state[0].addr, 16)
    copyMem(result[16].addr, t_state[12].addr, 16)

    # SECURITY: Clear sensitive intermediate state from stack
    secureZeroArray(t_state)

proc xchacha20_init(key: Key, nonce: XNonce): XKN =
    # SECURITY: Validate input lengths
    if key.len != 32:
        raise newException(ValueError, "SECURITY: Key must be exactly 32 bytes")
    if nonce.len != 24:
        raise newException(ValueError, "SECURITY: XNonce must be exactly 24 bytes")
    
    var
        t_nonce: XKNonce
    
    # SECURITY: Bounds checking for nonce operations
    static: assert(sizeof(XNonce) == 24)
    static: assert(sizeof(XKNonce) == 16)
    static: assert(sizeof(Nonce) >= 12)
    
    copyMem(t_nonce[0].addr, nonce[0].unsafeAddr, 16)
    
    # SECURITY: Ensure we don't read past nonce bounds
    if nonce.len < 24:
        raise newException(IndexDefect, "SECURITY: Insufficient nonce length")
    copyMem(result.sub_nonce[4].addr, nonce[16].unsafeAddr, 8)
    result.sub_key = hchacha20(key, t_nonce)

proc xchacha20*(
    key: Key,
    nonce: XNonce,
    counter: var Counter = 0,
    plain_data: openArray[byte],
    cipher_data: var openArray[byte]) =
    var
        xkn: XKN
        c: ChaCha

    # Calculate a subkey from the first 16 bytes of the nonce and the key, using HChaCha20 (Section 2.2).
    # Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL bytes) with AEAD_CHACHA20_POLY1305 from [RFC8439] as normal. The definition for XChaCha20 is given in Section 2.3.

    xkn = xchacha20_init(key, nonce)
    c.key = xkn.sub_key
    c.nonce = xkn.sub_nonce
    c.counter = counter
    c.chacha20_xor(plain_data, cipher_data)

    # CRITICAL: Update caller's counter so subsequent calls don't reuse keystream
    counter = c.counter

    # SECURITY: Clear sensitive key material from stack
    secureZeroArray(xkn.sub_key)
    secureZeroArray(c.key)
    secureZeroArray(c.state)
    secureZeroArray(c.initial_state)

proc xchacha20_aead_poly1305_encrypt*(
    key: Key,
    nonce: XNonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    plain_data: var openArray[byte],
    cipher_data: var openArray[byte],
    tag: var Tag
    ) =
    var
        xkn: XKN
    xkn = xchacha20_init(key, nonce)
    chacha20_aead_poly1305_encrypt(
        xkn.sub_key,
        xkn.sub_nonce,
        counter,
        auth_data,
        plain_data,
        cipher_data,
        tag
    )
    # SECURITY: Clear sensitive sub-key from stack
    secureZeroArray(xkn.sub_key)

# SECURITY: Verified decryption that checks tag BEFORE releasing plaintext
proc xchacha20_aead_poly1305_decrypt_verified*(
    key: Key,
    nonce: XNonce,
    counter: var Counter = 0,
    auth_data: openArray[byte],
    cipher_data: openArray[byte],
    plain_data: var openArray[byte],
    expected_tag: Tag): bool =
    var
        xkn: XKN
    xkn = xchacha20_init(key, nonce)
    result = chacha20_aead_poly1305_decrypt_verified(
        xkn.sub_key,
        xkn.sub_nonce,
        counter,
        auth_data,
        cipher_data,
        plain_data,
        expected_tag
    )
    # SECURITY: Clear sensitive sub-key from stack
    secureZeroArray(xkn.sub_key)