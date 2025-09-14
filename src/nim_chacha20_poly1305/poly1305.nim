# Secure Poly1305 implementation using libsodium
# This completely eliminates the side-channel vulnerability by using
# libsodium's constant-time implementation

import common

# Use the libsodium-based implementation
import poly1305_libsodium

# Export the types and procedures
export poly1305_libsodium.Poly1305, poly1305_libsodium.poly_pad

# Wrapper procedures that maintain API compatibility
proc poly1305_init*(poly: var Poly1305, key: Key) =
    poly1305_libsodium.poly1305_init(poly, key)

proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    poly1305_libsodium.poly1305_update(poly, data)
