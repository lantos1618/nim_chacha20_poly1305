# Constant-time Poly1305 implementation
# This version prevents side-channel attacks by using fixed-time operations

import common

# Re-export the constant-time implementation
import poly1305_ct

# Export the types and procedures we need
export poly1305_ct.Poly1305

#   padding1 -- the padding is up to 15 zero bytes, and it brings
#          the total length so far to an integral multiple of 16.  If the
#          length of the AAD was already an integral multiple of 16 bytes,
#          this field is zero-length.
func poly_pad*(data: openArray[byte], x: int ): seq[byte] =
    if data.len() mod x != 0:
        result.setLen(x - (data.len() mod x))

# Wrapper procedures that maintain API compatibility
proc poly1305_init*(poly: var Poly1305, key: Key) =
    poly1305_ct.poly1305_init(poly, key)

proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    poly1305_ct.poly1305_update(poly, data)
    poly1305_ct.poly1305_finalize(poly)
