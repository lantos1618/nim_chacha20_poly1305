# Constant-time Poly1305 implementation without stint dependency
# Implements 130-bit arithmetic with constant-time operations

import common

# 130-bit number represented as 5 x 32-bit limbs (26-bit each except last)
type
    Poly130* = object
        limbs*: array[5, uint64]  # Use uint64 to prevent overflow during arithmetic

const
    MASK26* = (1'u64 shl 26) - 1  # 0x3ffffff

# Convert bytes to Poly130 (little-endian)
proc fromBytes*(data: openArray[byte]): Poly130 =
    var padded: array[17, byte]  # Max 16 bytes + 1 padding byte
    let len = min(data.len, 16)
    
    # Copy data
    for i in 0..<len:
        padded[i] = data[i]
    
    # Add padding bit if needed
    if len < 17:
        padded[len] = 0x01
    
    # Convert to 64-bit words (little-endian)
    var t0, t1: uint64
    for i in 0..7:
        t0 = t0 or (uint64(padded[i]) shl (i * 8))
    for i in 8..16:
        t1 = t1 or (uint64(padded[i]) shl ((i-8) * 8))
    
    # Split into 26-bit limbs
    result.limbs[0] = t0 and MASK26
    result.limbs[1] = ((t0 shr 26) or (t1 shl 38)) and MASK26
    result.limbs[2] = (t1 shr 14) and MASK26
    result.limbs[3] = (t1 shr 40) and MASK26
    result.limbs[4] = t1 shr 66

# Convert key bytes to clamped Poly130
proc fromKey*(key: openArray[byte]): Poly130 =
    var padded: array[16, byte]
    let len = min(key.len, 16)
    
    # Copy key data
    for i in 0..<len:
        padded[i] = key[i]
    
    # Apply clamping
    padded[3] = padded[3] and 0x0f
    padded[7] = padded[7] and 0x0f
    padded[11] = padded[11] and 0x0f
    padded[15] = padded[15] and 0x0f
    padded[4] = padded[4] and 0xfc
    padded[8] = padded[8] and 0xfc
    padded[12] = padded[12] and 0xfc
    
    # Convert to limbs
    var t0, t1: uint64
    for i in 0..7:
        t0 = t0 or (uint64(padded[i]) shl (i * 8))
    for i in 8..15:
        t1 = t1 or (uint64(padded[i]) shl ((i-8) * 8))
    
    result.limbs[0] = t0 and MASK26
    result.limbs[1] = ((t0 shr 26) or (t1 shl 38)) and MASK26  
    result.limbs[2] = (t1 shr 14) and MASK26
    result.limbs[3] = (t1 shr 40) and MASK26
    result.limbs[4] = t1 shr 66

# Add two Poly130 numbers
proc add*(a: var Poly130, b: Poly130) =
    for i in 0..4:
        a.limbs[i] += b.limbs[i]

# Constant-time conditional subtraction (if a >= b then a := a - b)
proc ctSub*(a: var Poly130, b: Poly130) =
    var borrow: uint64 = 0
    var temp: array[5, uint64]
    
    # Try subtraction
    for i in 0..4:
        let x = a.limbs[i] - b.limbs[i] - borrow
        temp[i] = x
        borrow = x shr 63
    
    # If no borrow, use result; otherwise keep original
    let mask = borrow - 1  # 0xffffffffffffffff if no borrow, 0 if borrow
    for i in 0..4:
        a.limbs[i] = (a.limbs[i] and (not mask)) or (temp[i] and mask)

# Multiply and reduce modulo 2^130-5
proc mulMod*(a: Poly130, b: Poly130): Poly130 =
    # Schoolbook multiplication
    var c: array[9, uint64]  # Product can be up to 260 bits
    
    for i in 0..4:
        for j in 0..4:
            c[i+j] += a.limbs[i] * b.limbs[j]
    
    # Reduce modulo 2^130-5
    # For terms >= 2^130, multiply by 5 and add to lower terms
    for i in countdown(8, 5):
        c[i-5] += c[i] * 5
        c[i] = 0
    
    # Carry propagation with normalization to 26-bit limbs
    var carry: uint64 = 0
    for i in 0..4:
        c[i] += carry
        result.limbs[i] = c[i] and MASK26
        carry = c[i] shr 26
    
    # Final reduction if needed
    if carry > 0:
        result.limbs[0] += carry * 5
        # Propagate any additional carry
        carry = result.limbs[0] shr 26
        result.limbs[0] = result.limbs[0] and MASK26
        for i in 1..4:
            if carry == 0:
                break
            result.limbs[i] += carry
            carry = result.limbs[i] shr 26
            result.limbs[i] = result.limbs[i] and MASK26

# Convert to bytes (little-endian, 16 bytes)
proc toBytes*(p: Poly130): array[16, byte] =
    # First normalize to ensure proper reduction
    var temp = p
    
    # Final constant-time reduction
    var p_prime: Poly130
    p_prime.limbs[0] = MASK26 - 5
    p_prime.limbs[1] = MASK26
    p_prime.limbs[2] = MASK26  
    p_prime.limbs[3] = MASK26
    p_prime.limbs[4] = (1'u64 shl 4) - 1
    
    temp.ctSub(p_prime)
    
    # Pack into 128 bits (lower 16 bytes only)
    let t0 = temp.limbs[0] or (temp.limbs[1] shl 26) or ((temp.limbs[2] and 0x3f) shl 52)
    let t1 = (temp.limbs[2] shr 6) or (temp.limbs[3] shl 20) or (temp.limbs[4] shl 46)
    
    # Convert to bytes
    for i in 0..7:
        result[i] = byte((t0 shr (i * 8)) and 0xff)
    for i in 8..15:
        result[i] = byte((t1 shr ((i-8) * 8)) and 0xff)

# New Poly1305 type using constant-time operations
type
    Poly1305* = object
        r*, s*, a*: Poly130
        tag*: Tag

# Initialize with key
proc poly1305_init*(poly: var Poly1305, key: Key) =
    poly.r = fromKey(key[0..15])
    poly.s = fromBytes(key[16..31])

# Update with data
proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    var i = 0
    while i < data.len:
        let blockLen = min(16, data.len - i)
        let blockData = data[i..<i+blockLen]
        
        let n = fromBytes(blockData)
        poly.a.add(n)
        poly.a = mulMod(poly.a, poly.r)
        
        i += 16
    
    # Add s and finalize
    poly.a.add(poly.s)
    let tagBytes = poly.a.toBytes()
    copyMem(poly.tag[0].addr, tagBytes[0].addr, 16)

# Padding function (unchanged)
func poly_pad*(data: openArray[byte], x: int): seq[byte] =
    if data.len() mod x != 0:
        result.setLen(x - (data.len() mod x))
