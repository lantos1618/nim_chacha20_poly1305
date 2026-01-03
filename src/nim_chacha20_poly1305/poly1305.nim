# Constant-time Poly1305 implementation without external dependencies
# http://cr.yp.to/mac/poly1305-20050329.pdf
# https://datatracker.ietf.org/doc/html/rfc7539

import common
import helpers

# 130-bit number represented as 5 x 32-bit limbs (26-bit each except last)
type
    Poly130* = object
        limbs*: array[5, uint64]  # Use uint64 to prevent overflow during arithmetic

const
    MASK26* = (1'u64 shl 26) - 1  # 0x3ffffff

# Convert bytes to Poly130 (little-endian) with 0x01 padding for message blocks
# The 130-bit representation: 5 limbs of 26 bits each
# Input: up to 16 data bytes + implicit 0x01 padding byte at position len
proc fromBytes*(data: openArray[byte]): Poly130 =
    var padded: array[17, byte]  # Max 16 bytes + 1 padding byte
    let len = min(data.len, 16)

    # Copy data
    for i in 0..<len:
        padded[i] = data[i]

    # Add padding bit (0x01) at position len
    padded[len] = 0x01

    # Convert to 64-bit words (little-endian)
    # t0 = bytes 0-7 (bits 0-63)
    # t1 = bytes 8-15 (bits 64-127)
    # hibit = byte 16 (the 0x01 padding, provides bit 128)
    var t0, t1: uint64
    for i in 0..7:
        t0 = t0 or (uint64(padded[i]) shl (i * 8))
    for i in 0..7:
        t1 = t1 or (uint64(padded[i + 8]) shl (i * 8))
    let hibit = uint64(padded[16])  # 0x01 for full blocks, 0x01 for partial too

    # Split into 26-bit limbs
    # 130 bits total: limbs[0..4] each hold 26 bits
    # Bit layout:
    #   limbs[0] = bits 0-25
    #   limbs[1] = bits 26-51
    #   limbs[2] = bits 52-77
    #   limbs[3] = bits 78-103
    #   limbs[4] = bits 104-129
    result.limbs[0] = t0 and MASK26
    result.limbs[1] = (t0 shr 26) and MASK26
    result.limbs[2] = ((t0 shr 52) or (t1 shl 12)) and MASK26
    result.limbs[3] = (t1 shr 14) and MASK26
    result.limbs[4] = (t1 shr 40) or (hibit shl 24)

# Convert key bytes to clamped Poly130 (r value, 124 bits after clamping)
proc fromKey*(key: openArray[byte]): Poly130 =
    var padded: array[16, byte]
    let len = min(key.len, 16)

    # Copy key data
    for i in 0..<len:
        padded[i] = key[i]

    # Apply clamping per RFC 8439
    padded[3] = padded[3] and 0x0f
    padded[7] = padded[7] and 0x0f
    padded[11] = padded[11] and 0x0f
    padded[15] = padded[15] and 0x0f
    padded[4] = padded[4] and 0xfc
    padded[8] = padded[8] and 0xfc
    padded[12] = padded[12] and 0xfc

    # Convert to 64-bit words (little-endian)
    var t0, t1: uint64
    for i in 0..7:
        t0 = t0 or (uint64(padded[i]) shl (i * 8))
    for i in 0..7:
        t1 = t1 or (uint64(padded[i + 8]) shl (i * 8))

    # Split into 26-bit limbs (128-bit value, no padding)
    result.limbs[0] = t0 and MASK26
    result.limbs[1] = (t0 shr 26) and MASK26
    result.limbs[2] = ((t0 shr 52) or (t1 shl 12)) and MASK26
    result.limbs[3] = (t1 shr 14) and MASK26
    result.limbs[4] = (t1 shr 40)  # Only 24 bits here after clamping

# Convert 16-byte s value to Poly130 (NO padding - raw 128-bit value)
# This is used for the s part of the key, which is added to the accumulator
# at the end of Poly1305. Unlike message blocks, s has no padding byte.
proc fromS*(data: openArray[byte]): Poly130 =
    var padded: array[16, byte]
    let len = min(data.len, 16)

    # Copy data (NO padding byte for s value!)
    for i in 0..<len:
        padded[i] = data[i]

    # Convert to 64-bit words (little-endian)
    var t0, t1: uint64
    for i in 0..7:
        t0 = t0 or (uint64(padded[i]) shl (i * 8))
    for i in 0..7:
        t1 = t1 or (uint64(padded[i + 8]) shl (i * 8))

    # Split into 26-bit limbs (128-bit value, no 0x01 padding)
    result.limbs[0] = t0 and MASK26
    result.limbs[1] = (t0 shr 26) and MASK26
    result.limbs[2] = ((t0 shr 52) or (t1 shl 12)) and MASK26
    result.limbs[3] = (t1 shr 14) and MASK26
    result.limbs[4] = (t1 shr 40)  # Only 24 bits (bits 104-127)

# Add two Poly130 numbers
proc add*(a: var Poly130, b: Poly130) =
    for i in 0..4:
        a.limbs[i] += b.limbs[i]

# Constant-time conditional subtraction (if a >= b then a := a - b)
# Properly handles 26-bit limb arithmetic without garbage bits
proc ctSub*(a: var Poly130, b: Poly130) =
    var borrow: uint64 = 0
    var temp: array[5, uint64]

    # Try subtraction using offset to prevent underflow
    # Add 2^26 to each limb before subtracting, then check if we borrowed
    for i in 0..4:
        # Add 2^26 to prevent uint64 underflow, then subtract
        let x = (a.limbs[i] + (1'u64 shl 26)) - b.limbs[i] - borrow
        # Result limb is lower 26 bits
        temp[i] = x and MASK26
        # If x < 2^26 (bit 26 not set), we needed the offset, so borrow = 1
        borrow = 1'u64 - (x shr 26)

    # If no final borrow, use result; otherwise keep original
    # borrow = 0 means a >= b, so mask = 0xFFFFFFFFFFFFFFFF
    # borrow = 1 means a < b, so mask = 0
    let mask = borrow - 1
    for i in 0..4:
        a.limbs[i] = (a.limbs[i] and (not mask)) or (temp[i] and mask)

# Multiply and reduce modulo 2^130-5
# Fully constant-time implementation - no data-dependent branches
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

    # Branchless final reduction
    # Always perform carry * 5 addition (carry may be 0, which is fine)
    result.limbs[0] += carry * 5

    # Always propagate carries through ALL limbs - no early exit
    # This ensures constant-time execution regardless of data values
    carry = result.limbs[0] shr 26
    result.limbs[0] = result.limbs[0] and MASK26

    result.limbs[1] += carry
    carry = result.limbs[1] shr 26
    result.limbs[1] = result.limbs[1] and MASK26

    result.limbs[2] += carry
    carry = result.limbs[2] shr 26
    result.limbs[2] = result.limbs[2] and MASK26

    result.limbs[3] += carry
    carry = result.limbs[3] shr 26
    result.limbs[3] = result.limbs[3] and MASK26

    result.limbs[4] += carry
    # No need to mask limbs[4] as it can hold slightly more than 26 bits
    # Final reduction in toBytes() handles this via ctSub

# Convert to bytes (little-endian, 16 bytes)
# Reconstructs 128-bit value from 5 x 26-bit limbs
proc toBytes*(p: Poly130): array[16, byte] =
    var temp = p

    # First, normalize limbs by propagating carries
    # This is necessary because add() doesn't normalize
    var carry: uint64 = 0
    for i in 0..3:
        temp.limbs[i] += carry
        carry = temp.limbs[i] shr 26
        temp.limbs[i] = temp.limbs[i] and MASK26
    temp.limbs[4] += carry

    # Handle wrap-around: if limbs[4] >= 2^26, reduce mod 2^130-5
    # Since 2^130 ≡ 5 (mod 2^130-5), carry from limbs[4] multiplies by 5
    carry = temp.limbs[4] shr 26
    temp.limbs[4] = temp.limbs[4] and MASK26
    temp.limbs[0] += carry * 5

    # Propagate any new carries
    carry = temp.limbs[0] shr 26
    temp.limbs[0] = temp.limbs[0] and MASK26
    for i in 1..4:
        temp.limbs[i] += carry
        carry = temp.limbs[i] shr 26
        temp.limbs[i] = temp.limbs[i] and MASK26

    # If there's still a carry out of limbs[4], fold it back
    # This handles edge cases where value >= 2^130 after first reduction
    # 2^130 ≡ 5 (mod 2^130-5), so carry * 5 must be added to limbs[0]
    temp.limbs[0] += carry * 5
    carry = temp.limbs[0] shr 26
    temp.limbs[0] = temp.limbs[0] and MASK26
    temp.limbs[1] += carry
    # No further propagation needed: carry * 5 <= 5, so limbs[0] + 5 < 2^27
    # and limbs[1] + 1 cannot overflow since limbs[1] was just masked to 26 bits

    # Final constant-time reduction modulo 2^130-5
    # If accumulator >= 2^130-5, subtract it
    # 2^130 - 5 in binary: all 130 bits set except bit 2
    var p_prime: Poly130
    p_prime.limbs[0] = MASK26 - 4  # 2^26 - 5 = (2^26-1) - 4
    p_prime.limbs[1] = MASK26
    p_prime.limbs[2] = MASK26
    p_prime.limbs[3] = MASK26
    p_prime.limbs[4] = MASK26

    temp.ctSub(p_prime)

    # Pack 5 x 26-bit limbs back into 128 bits
    # Bit layout:
    #   limbs[0] = bits 0-25
    #   limbs[1] = bits 26-51
    #   limbs[2] = bits 52-77
    #   limbs[3] = bits 78-103
    #   limbs[4] = bits 104-127 (only 24 bits for 128-bit output)
    let t0 = temp.limbs[0] or (temp.limbs[1] shl 26) or ((temp.limbs[2] and 0xfff) shl 52)
    let t1 = (temp.limbs[2] shr 12) or (temp.limbs[3] shl 14) or (temp.limbs[4] shl 40)

    # Convert to bytes (little-endian)
    for i in 0..7:
        result[i] = byte((t0 shr (i * 8)) and 0xff)
    for i in 0..7:
        result[i + 8] = byte((t1 shr (i * 8)) and 0xff)

# Poly1305 type using constant-time operations
type
    Poly1305* = object
        r*, s*, a*: Poly130
        buffer*: array[16, byte]  # Buffer for partial blocks
        bufferLen*: int           # Current bytes in buffer
        tag*: Tag

# Initialize with key
proc poly1305_init*(poly: var Poly1305, key: Key) =
    poly.r = fromKey(key[0..15])
    poly.s = fromS(key[16..31])  # Use fromS for s value (no padding)
    poly.bufferLen = 0
    for i in 0..15:
        poly.buffer[i] = 0

# Process a single complete 16-byte block (internal use)
proc processBlock(poly: var Poly1305, blockData: openArray[byte]) =
    let n = fromBytes(blockData)
    poly.a.add(n)
    poly.a = mulMod(poly.a, poly.r)

# Update with data (process blocks) - handles arbitrary chunk sizes correctly
proc poly1305_update*(poly: var Poly1305, data: openArray[byte]) =
    var offset = 0

    # If we have buffered data, try to complete a block
    if poly.bufferLen > 0:
        let needed = 16 - poly.bufferLen
        let available = min(needed, data.len)
        for i in 0..<available:
            poly.buffer[poly.bufferLen + i] = data[i]
        poly.bufferLen += available
        offset = available

        # If we have a complete block, process it
        if poly.bufferLen == 16:
            poly.processBlock(poly.buffer)
            poly.bufferLen = 0

    # Process complete 16-byte blocks directly from input
    while offset + 16 <= data.len:
        poly.processBlock(data[offset..<offset+16])
        offset += 16

    # Buffer any remaining partial block (do NOT process yet - no padding!)
    let remaining = data.len - offset
    if remaining > 0:
        for i in 0..<remaining:
            poly.buffer[poly.bufferLen + i] = data[offset + i]
        poly.bufferLen += remaining

# Finalize and produce tag (add s value)
proc poly1305_final*(poly: var Poly1305): Tag =
    # Process any remaining buffered data (final partial block with padding)
    if poly.bufferLen > 0:
        # fromBytes adds the 0x01 padding automatically for partial blocks
        poly.processBlock(poly.buffer[0..<poly.bufferLen])
        poly.bufferLen = 0

    # Add s and produce final tag
    poly.a.add(poly.s)
    let tagBytes = poly.a.toBytes()
    copyMem(result[0].addr, tagBytes[0].addr, 16)
    poly.tag = result

# Padding function
func poly_pad*(data: openArray[byte], x: int): seq[byte] =
    if data.len() mod x != 0:
        result.setLen(x - (data.len() mod x))

# Constant-time MAC verification to prevent timing attacks
proc poly1305_verify*(expected_tag: Tag, computed_tag: Tag): bool =
    # Constant-time comparison to prevent timing side-channel attacks
    var diff: byte = 0
    for i in 0..<16:
        diff = diff or (expected_tag[i] xor computed_tag[i])
    result = diff == 0

# Secure finalization that clears sensitive state
# Uses volatile writes to prevent Dead Store Elimination
proc poly1305_finalize*(poly: var Poly1305) =
    # Clear sensitive key material from memory using volatile writes
    secureZeroArray(poly.r.limbs)
    secureZeroArray(poly.s.limbs)
    secureZeroArray(poly.a.limbs)
    secureZero(poly.buffer)
    poly.bufferLen = 0
    memoryBarrier()  # Ensure clears complete before function returns

# Legacy compatibility
proc poly1305_clamp*(poly: var Poly1305) =
    # Clamping is now handled internally
    discard