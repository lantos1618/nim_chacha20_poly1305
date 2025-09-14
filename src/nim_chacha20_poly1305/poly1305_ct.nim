# poly1305_ct.nim - Constant-time Poly1305 implementation
# This replaces the vulnerable variable-time big-integer arithmetic with
# constant-time 26-bit limb arithmetic to prevent side-channel attacks

import common
import bitops

# ----------------------------------------------------------------------
#  Private helpers: 26-bit limb representation, constant-time helpers
# ----------------------------------------------------------------------
type
  PolyKey*  = array[16, byte]          # first 16 bytes of the 32-byte AEAD key
  Limb      = uint64                   # we stay in 64 bits
  Limbs130  = object                   # 5×26-bit = 130 bits
    l0, l1, l2, l3, l4: Limb           # little-endian limbs

const MASK26 = (1'u64 shl 26) - 1      # 0x03ffffff

# ----------------------------------------------------------------------
proc loadR(key: PolyKey): Limbs130 =
  # read 16-byte r, clamp, and split into 26-bit limbs
  var t0 = cast[ptr uint64](key[0].addr)[]
  var t1 = cast[ptr uint64](key[8].addr)[]
  
  # Apply clamping to the 128-bit key
  t0 = t0 and 0x0ffffffc0ffffff'u64
  t1 = t1 and 0x0ffffffc0fffffff'u64
  
  # Convert to limbs
  result.l0 = t0 and MASK26
  result.l1 = ((t0 shr 26) or (t1 shl 38)) and MASK26
  result.l2 = (t1 shr 14) and MASK26
  result.l3 = (t1 shr 40) and MASK26
  result.l4 = (t1 shr 66) and ((1'u64 shl 4) - 1)  # only 4 bits

proc ctIfSub(a: var Limbs130, b: Limbs130): void {.inline.} =
  # constant-time: subtract b from a if a ≥ b
  var borrow: uint64 = 0
  var tmp: array[5, uint64]
  let bb = [b.l0, b.l1, b.l2, b.l3, b.l4]
  let aa = [a.l0, a.l1, a.l2, a.l3, a.l4]
  
  for i in 0..4:
    let x = aa[i] - bb[i] - borrow
    tmp[i] = x
    borrow = (x shr 63) and 1          # 1 if we wrapped, else 0
  
  # mask = 0xFFFF…  if no borrow (a≥b), 0 otherwise
  let mask = (borrow - 1)  # 0xffffffffffffffff when borrow==0, 0 when borrow==1
  
  a.l0 = aa[0] xor (mask and (aa[0] xor tmp[0]))
  a.l1 = aa[1] xor (mask and (aa[1] xor tmp[1]))
  a.l2 = aa[2] xor (mask and (aa[2] xor tmp[2]))
  a.l3 = aa[3] xor (mask and (aa[3] xor tmp[3]))
  a.l4 = aa[4] xor (mask and (aa[4] xor tmp[4]))

# ----------------------------------------------------------------------
type
  Poly1305* = object
    r*: Limbs130         # clamped key
    s*: array[16, byte]  # second half of the 32-byte key
    h: Limbs130          # accumulator
    tag*: Tag

proc poly1305_init*(p: var Poly1305, key: Key) =
  var polykey: PolyKey
  copyMem(polykey.addr, key[0].addr, 16)
  p.r = loadR(polykey)
  copyMem(p.s.addr, key[16].addr, 16)
  # Initialize accumulator to zero
  p.h.l0 = 0
  p.h.l1 = 0
  p.h.l2 = 0
  p.h.l3 = 0
  p.h.l4 = 0

# ----------------------------------------------------------------------
proc mulAdd(h: var Limbs130, r: Limbs130, m: Limbs130) =
  # h = (h + m) * r  (mod 2^130-5)    — all constant-time
  # 1. add
  var h0 = h.l0 + m.l0
  var h1 = h.l1 + m.l1
  var h2 = h.l2 + m.l2
  var h3 = h.l3 + m.l3
  var h4 = h.l4 + m.l4
  
  # 2. multiply (schoolbook, 64-bit intermediates, limbs fit in 2^64)
  var t0 = h0*r.l0 + h1*r.l4*5 + h2*r.l3*5 + h3*r.l2*5 + h4*r.l1*5
  var t1 = h0*r.l1 + h1*r.l0     + h2*r.l4*5 + h3*r.l3*5 + h4*r.l2*5
  var t2 = h0*r.l2 + h1*r.l1     + h2*r.l0     + h3*r.l4*5 + h4*r.l3*5
  var t3 = h0*r.l3 + h1*r.l2     + h2*r.l1     + h3*r.l0     + h4*r.l4*5
  var t4 = h0*r.l4 + h1*r.l3     + h2*r.l2     + h3*r.l1     + h4*r.l0
  
  # 3. carry / reduce  (two passes, fixed operations)
  var c: uint64
  c = t0 shr 26; h.l0 = t0 and MASK26; t1 += c
  c = t1 shr 26; h.l1 = t1 and MASK26; t2 += c
  c = t2 shr 26; h.l2 = t2 and MASK26; t3 += c
  c = t3 shr 26; h.l3 = t3 and MASK26; t4 += c
  c = t4 shr 26; h.l4 = t4 and MASK26; h.l0 += c*5
  
  # one more carry to make sure h fits 130 bits
  c = h.l0 shr 26; h.l0 = h.l0 and MASK26; h.l1 += c
  
  # 4. conditional subtract p in constant time
  var p1305: Limbs130
  p1305.l0 = MASK26 - 5        # (2^130 -5) in limbs
  p1305.l1 = MASK26
  p1305.l2 = MASK26
  p1305.l3 = MASK26
  p1305.l4 = (1'u64 shl 4) - 1 # only upper 4 bits used
  ctIfSub(h, p1305)

# ----------------------------------------------------------------------
proc poly1305_update*(p: var Poly1305, msg: openArray[byte]) =
  var i = 0
  while i < msg.len:
    var blk: array[17, byte]
    let left = min(16, msg.len - i)
    copyMem(blk[0].addr, msg[i].addr, left)
    blk[left] = 0x01              # the "1" bit
    
    # Fill remaining bytes with zero
    for j in (left + 1)..16:
      blk[j] = 0
    
    # Convert to limbs
    var m: Limbs130
    var t0 = cast[ptr uint64](blk[0].addr)[]         # little endian
    var t1 = cast[ptr uint64](blk[8].addr)[]
    
    m.l0 = t0              and MASK26
    m.l1 = ((t0 shr 26) or (t1 shl 38))     and MASK26
    m.l2 = (t1 shr 14)     and MASK26
    m.l3 = (t1 shr 40)     and MASK26
    m.l4 = (t1 shr 66)
    
    mulAdd(p.h, p.r, m)
    i += 16

proc poly1305_finalize*(p: var Poly1305) =
  # convert h to 16-byte little-endian, then add s (just a 128-bit add)
  var g = p.h                     # copy, we may need it
  
  # second subtract (again const-time) to bring it < 2^128
  var p1305: Limbs130
  p1305.l0 = MASK26 - 5
  p1305.l1 = MASK26
  p1305.l2 = MASK26
  p1305.l3 = MASK26
  p1305.l4 = (1'u64 shl 4) - 1
  ctIfSub(g, p1305)
  
  # serialize lower 128 bits
  var t0 = g.l0 or (g.l1 shl 26) or ((g.l2 and 0x3f) shl 52)
  var t1 = (g.l2 shr 6) or (g.l3 shl 20) or (g.l4 shl 46)
  
  # Add s to the result with carry
  var s0 = cast[ptr uint64](p.s[0].addr)[]
  var s1 = cast[ptr uint64](p.s[8].addr)[]
  
  t0 += s0
  var carry = if t0 < s0: 1'u64 else: 0'u64
  t1 += s1 + carry
  
  cast[ptr uint64](p.tag[0].addr)[] = t0
  cast[ptr uint64](p.tag[8].addr)[] = t1
