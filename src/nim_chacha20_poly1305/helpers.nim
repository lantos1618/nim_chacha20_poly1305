# SECURITY-HARDENED Helper Functions for ChaCha20-Poly1305
# Provides safe conversions and utilities with bounds checking

import strutils

# SECURITY: Safe hex string to byte array conversion with validation
proc hexToBytes*(hexStr: string): seq[byte] =
    # Remove any whitespace and validate hex format
    let cleanHex = hexStr.replace(" ").replace("\n").replace("\t")
    
    if cleanHex.len mod 2 != 0:
        raise newException(ValueError, "SECURITY: Hex string must have even length")
    
    if cleanHex.len == 0:
        return @[]
    
    # Validate all characters are valid hex
    for i, c in cleanHex:
        if not c.isAlphaNumeric or not (c in {'0'..'9', 'a'..'f', 'A'..'F'}):
            raise newException(ValueError, "SECURITY: Invalid hex character at position " & $i)
    
    result.setLen(cleanHex.len div 2)
    
    # Convert hex pairs to bytes with error checking
    for i in 0..<result.len:
        let hexPair = cleanHex[i*2..(i*2+1)]
        try:
            result[i] = byte(parseHexInt(hexPair))
        except ValueError:
            raise newException(ValueError, "SECURITY: Invalid hex pair '" & hexPair & "' at position " & $(i*2))

# SECURITY: Safe byte array to hex string conversion
proc bytesToHex*(data: openArray[byte]): string =
    if data.len == 0:
        return ""
    
    result = newStringOfCap(data.len * 2)
    for b in data:
        result.add(b.toHex(2).toLower())

# SECURITY: Safe string to byte array conversion (UTF-8)
proc stringToBytes*(s: string): seq[byte] =
    if s.len == 0:
        return @[]
    
    result.setLen(s.len)
    for i in 0..<s.len:
        result[i] = byte(s[i])

# SECURITY: Safe byte array to string conversion with validation
proc bytesToString*(data: openArray[byte]): string =
    if data.len == 0:
        return ""
    
    result = newString(data.len)
    for i in 0..<data.len:
        # SECURITY: Validate printable ASCII to prevent issues
        let b = data[i]
        if b >= 32 and b <= 126:  # Printable ASCII range
            result[i] = char(b)
        else:
            result[i] = '?'  # Replace non-printable with ?

# SECURITY: Constant-time memory comparison
# NOTE: Length comparison is NOT constant-time. This is acceptable for
# fixed-size values (tags, keys, hashes) but reveals length for variable data.
# For fixed-size comparisons (like MAC tags), use constantTimeEqualsFixed.
proc constantTimeEquals*(a, b: openArray[byte]): bool =
    if a.len != b.len:
        return false

    var diff: byte = 0
    for i in 0..<a.len:
        diff = diff or (a[i] xor b[i])

    result = diff == 0

# SECURITY: Fully constant-time comparison for fixed-size arrays
# Both execution time and result are independent of input values
proc constantTimeEqualsFixed*[N: static int](a, b: array[N, byte]): bool =
    var diff: byte = 0
    for i in 0..<N:
        diff = diff or (a[i] xor b[i])
    result = diff == 0

# SECURITY: Secure memory clearing with DSE prevention
# Uses volatile writes to prevent Dead Store Elimination by the compiler
proc secureZero*[T](data: var openArray[T]) =
    # Use volatile pointer to prevent compiler from optimizing away the writes
    {.push stackTrace:off.}
    for i in 0..<data.len:
        let p = cast[ptr T](addr data[i])
        {.emit: ["*((volatile ", T, "*)(",  p, ")) = 0;"].}
    {.pop.}

# SECURITY: Secure zero for fixed-size arrays using volatile writes
proc secureZeroArray*[N: static int, T](data: var array[N, T]) =
    {.push stackTrace:off.}
    for i in 0..<N:
        let p = cast[ptr T](addr data[i])
        {.emit: ["*((volatile ", T, "*)(",  p, ")) = 0;"].}
    {.pop.}

# SECURITY: Memory barrier to prevent reordering
proc memoryBarrier*() {.inline.} =
    {.emit: "__asm__ __volatile__(\"\" ::: \"memory\");".}
