import stint

# http://cr.yp.to/mac/poly1305-20050329.pdf
# https://datatracker.ietf.org/doc/html/rfc7539

import common

type
    Poly1305* = object
        r*, s*, a*, n: UInt256
        tag*: Tag

# *  padding1 -- the padding is up to 15 zero bytes, and it brings
#          the total length so far to an integral multiple of 16.  If the
#          length of the AAD was already an integral multiple of 16 bytes,
#          this field is zero-length.
func poly_pad*(data: openArray[byte], x: int ): seq[byte] =
    if data.len() mod x != 0:
        result.setLen(x - (data.len() mod x))

#   clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
proc poly1305_clamp*(poly: var Poly1305) =
    poly.r = poly.r and fromHex(UInt256, "0x0ffffffc0ffffffc0ffffffc0fffffff")

proc poly1305_init*(poly:var Poly1305, key: Key) =
    poly.r = fromBytes(UInt256, key[0..15])
    poly.s = fromBytes(UInt256, key[16..31])

proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    # p = ( 2 ^ 130) - 5
    const p = fromHex(UInt256, "0x3fffffffffffffffffffffffffffffffb")
    poly.poly1305_clamp()
    
    # is there better way to do chucking? bits(len/size) + bits(remainder)
    for i in 1..(data.len() div 16):
        var t_data_block = data[((i-1)*16)..(i*(16)-1)]
        poly.n = fromBytes(UInt256, t_data_block  & @[0x01'u8]) # wouldn't need to do this if there were maths on array[byte]
        poly.a = poly.a + poly.n
        poly.a = (poly.r * poly.a) mod p
    
    # do remainder bytes
    if data.len mod 16 != 0:
        var t_data_block = data[(data.len() div 16)*16..data.high]
        poly.n = fromBytes(UInt256, t_data_block  & @[0x01'u8])
        poly.a = poly.a + poly.n
        poly.a = (poly.r * poly.a) mod p
    poly.a = poly.a + poly.s
    copyMem(poly.tag[0].addr, poly.a.addr, 16)

# todo
# proc poly1305_finalize(poly: var Poly1305) = 
#     copyMem(poly.tag[0].addr, poly.a.addr, 16)