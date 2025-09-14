
type
    Key* = array[32, byte]
    Nonce* = array[12, byte]
    State* = array[16, uint32]
    Tag* = array[16, byte]
    Block* = array[64, byte]
    Counter* = uint32

# SECURITY: Safe byte array to string conversion with bounds checking
proc`$$$`*(x: openArray[byte]): string =
    if x.len == 0:
        return ""
    result = newString(x.len)
    # SECURITY: Explicit bounds check before memory copy
    if result.len != x.len:
        raise newException(ValueError, "SECURITY: String allocation failed")
    copyMem(result[0].addr, x[0].unsafeAddr, x.len)