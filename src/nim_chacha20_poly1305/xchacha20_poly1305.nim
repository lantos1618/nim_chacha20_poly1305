# TODO
# warning! xchacha is still in draft
# https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-01.html
# https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-03.html
# https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt

import common, chacha20_poly1305, chacha20

type
    # extended key nonce
    XKN* = object
        sub_key*: Key
        sub_nonce*: Nonce
    XNonce* = array[24, byte]
    XKNonce* = array[16, byte]

proc hchacha20*(key: Key, xnonce: XKNonce): Key  =
    var t_state: State
    t_state[0] = 0x61707865'u32
    t_state[1] = 0x3320646e'u32
    t_state[2] = 0x79622d32'u32
    t_state[3] = 0x6b206574'u32
    copyMem(t_state[4].addr, key[0].unsafeAddr, 32) # (12 - 4)*(32 bits/ 8bytes)
    copyMem(t_state[12].addr, xnonce[0].unsafeAddr, 16) # (16- 12)*(32 bits/ 8bytes)
    t_state.chachca20_rounds()

    # echo t_state

    copyMem(result[0].addr, t_state[0].addr, 16)
    copyMem(result[16].addr, t_state[12].addr, 16)

proc xchacha20_init(key: Key, nonce: XNonce): XKN =
    var
        t_nonce: XKNonce
    copyMem(t_nonce[0].addr, nonce[0].unsafeAddr, 16)
    copyMem(result.sub_nonce[4].addr, nonce[16].unsafeAddr, 8)
    result.sub_key = hchacha20(key, t_nonce)

proc xchacha20*(
    key: Key,
    nonce: XNonce,
    counter:var Counter = 0,
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
    c.counter = counter # probably don't let user set this
    c.chacha20_xor(plain_data, cipher_data)

proc xchacha20_aead_poly1305_encrypt*(
    key: Key,
    nonce: XNonce,
    counter:var Counter = 0,
    auth_data: openArray[byte],
    plain_data: var openArray[byte],
    cipher_data: var openArray[byte],
    tag:var Tag
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

proc xchacha20_aead_poly1305_decrypt*(
    key: Key,
    nonce: XNonce,
    counter:var Counter = 0,
    auth_data: openArray[byte],
    plain_data: var openArray[byte],
    cipher_data: var openArray[byte],
    tag:var Tag
    ) =
    var
        xkn: XKN
    xkn = xchacha20_init(key, nonce)
    chacha20_aead_poly1305_decrypt(
        xkn.sub_key,
        xkn.sub_nonce,
        counter,
        auth_data,
        plain_data,
        cipher_data,
        tag
    )