# TODO
import common, chacha20, poly1305

# Helper to convert uint64 to little-endian bytes
proc uint64ToBytes(x: uint64): array[8, byte] =
    for i in 0..7:
        result[i] = byte((x shr (i * 8)) and 0xff)

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
        mac_data: seq[byte]

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

    mac_data = mac_data & @auth_data & poly_pad(@auth_data, 16)
    mac_data = mac_data & @cipher_data & poly_pad(@cipher_data, 16)
    mac_data = mac_data & @(uint64ToBytes(auth_data.len.uint64))
    mac_data = mac_data & @(uint64ToBytes(cipher_data.len.uint64))

    poly.poly1305_update(mac_data)
    tag = poly.tag

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