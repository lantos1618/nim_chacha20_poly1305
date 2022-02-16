
type
    Key* = array[32, byte]
    Nonce* = array[12, byte]
    State* = array[16, uint32]
    Tag* = array[16, byte]
    Block* = array[64, byte]
    Counter* = uint32

proc`$$$`*(x: openArray[byte]): string =
    result = newString(x.len)
    copyMem(result[0].addr, x[0].unsafeAddr, x.len)