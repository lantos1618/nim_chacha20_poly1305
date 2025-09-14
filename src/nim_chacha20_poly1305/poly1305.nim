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
    poly.r = fromBytes(UInt256, key[0..15], littleEndian)
    poly.s = fromBytes(UInt256, key[16..31], littleEndian)

# Constant-time modular reduction for 2^130-5
proc poly1305_reduce_ct(x: var UInt256) =
    # p = 2^130 - 5 = 0x3fffffffffffffffffffffffffffffffb
    const p = fromHex(UInt256, "0x3fffffffffffffffffffffffffffffffb")
    
    # Constant-time conditional subtraction
    # If x >= p then x = x - p, else x = x
    let x_bytes = x.toBytesLE()
    let p_bytes = p.toBytesLE()
    
    var temp_bytes: array[32, byte]
    var borrow: uint64 = 0
    
    # Perform subtraction x - p
    for i in 0..31:
        let diff = uint64(x_bytes[i]) - uint64(p_bytes[i]) - borrow
        temp_bytes[i] = byte(diff and 0xFF)
        borrow = (diff shr 63) and 1
    
    # If no borrow occurred, x >= p, so use subtraction result
    # Otherwise keep original x
    let use_sub = (borrow == 0)
    let mask: byte = if use_sub: 0xFF else: 0x00
    
    # Constant-time conditional move
    for i in 0..31:
        temp_bytes[i] = (x_bytes[i] and (not mask)) or (temp_bytes[i] and mask)
    
    x = fromBytes(UInt256, temp_bytes, littleEndian)

# Constant-time multiplication and reduction
proc poly1305_mulmod_ct(a, b: UInt256): UInt256 =
    result = a * b
    poly1305_reduce_ct(result)

proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    poly.poly1305_clamp()
    
    # is there better way to do chucking? bits(len/size) + bits(remainder)
    for i in 1..(data.len() div 16):
        var t_data_block = data[((i-1)*16)..(i*(16)-1)]
        poly.n = fromBytes(UInt256, t_data_block  & @[0x01'u8], littleEndian) # wouldn't need to do this if there were maths on array[byte]
        poly.a = poly.a + poly.n
        poly.a = poly1305_mulmod_ct(poly.r, poly.a)  # FIXED: constant-time
    
    # do remainder bytes
    if data.len mod 16 != 0:
        var t_data_block = data[(data.len() div 16)*16..data.high]
        poly.n = fromBytes(UInt256, t_data_block  & @[0x01'u8], littleEndian)
        poly.a = poly.a + poly.n
        poly.a = poly1305_mulmod_ct(poly.r, poly.a)  # FIXED: constant-time
    poly.a = poly.a + poly.s
    copyMem(poly.tag[0].addr, poly.a.addr, 16)

# todo
# proc poly1305_finalize(poly: var Poly1305) = 
#     copyMem(poly.tag[0].addr, poly.a.addr, 16)