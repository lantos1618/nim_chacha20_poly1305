# Replacement using libsodium's constant-time Poly1305 implementation
# This completely eliminates the side-channel vulnerability

import common
import libsodium/sodium

type
    Poly1305* = object
        key*: string           # Store key as string for libsodium
        tag*: Tag
        data*: seq[byte]       # Accumulate data for single update call

func poly_pad*(data: openArray[byte], x: int ): seq[byte] =
    if data.len() mod x != 0:
        result.setLen(x - (data.len() mod x))

proc poly1305_init*(poly: var Poly1305, key: Key) =
    poly.key = newStringOfCap(32)
    poly.key.setLen(32)
    copyMem(poly.key[0].addr, key[0].addr, 32)
    poly.data = @[]

proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    # Accumulate data - we'll process it all at once
    poly.data.add(@data)
    
    # Convert data to string for libsodium
    var message = newStringOfCap(poly.data.len)
    message.setLen(poly.data.len)
    if poly.data.len > 0:
        copyMem(message[0].addr, poly.data[0].addr, poly.data.len)
    
    # Use libsodium's crypto_onetimeauth which implements Poly1305
    let auth_result = crypto_onetimeauth(message, poly.key)
    
    # Copy result to tag
    copyMem(poly.tag[0].addr, auth_result[0].addr, 16)
