type
    Key* = array[32, byte]
    Nonce* = array[12, byte]
    State* = array[16, uint32]
    Tag* = array[16, byte]
    Block* = array[64, byte]
    Counter* = uint32