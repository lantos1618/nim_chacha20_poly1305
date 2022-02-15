import bitops, endians
import stint
import common

# chacha20
# https://datatracker.ietf.org/doc/html/rfc7539

type
    ChaCha* = object
        key*: Key
        nonce*: Nonce
        counter*: Counter
        initial_state*: State
        state*: State
    
proc chacha20_quarter_round*(a, b, c, d: var uint32) =
    a = a + b; d= d.xor(a); d = d.rotateLeftBits(16)
    c = c + d; b= b.xor(c); b = b.rotateLeftBits(12)
    a = a + b; d= d.xor(a); d = d.rotateLeftBits(8)
    c = c + d; b= b.xor(c); b = b.rotateLeftBits(7)

proc chacha20_inner_block*(x: var State) =
    # Each round consists of four quarter-rounds, and
    # they are run as follows.  Quarter rounds 1-4 are part of a "column"
    # round, while 5-8 are part of a "diagonal" round:
    # column
    chacha20_quarter_round(x[0], x[4], x[8], x[12])
    chacha20_quarter_round(x[1], x[5], x[9], x[13])
    chacha20_quarter_round(x[2], x[6], x[10], x[14])
    chacha20_quarter_round(x[3], x[7], x[11], x[15])
    # diagonal
    chacha20_quarter_round(x[0], x[5], x[10], x[15])
    chacha20_quarter_round(x[1], x[6], x[11], x[12])
    chacha20_quarter_round(x[2], x[7], x[8], x[13])
    chacha20_quarter_round(x[3], x[4], x[9], x[14])

proc chacha20_init_state*(c: var ChaCha) =
    # The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
    c.initial_state[0] = 0x61707865'u32
    c.initial_state[1] = 0x3320646e'u32
    c.initial_state[2] = 0x79622d32'u32
    c.initial_state[3] = 0x6b206574'u32
    # The next eight words (4-11) are taken from the 256-bit key by
    # reading the bytes in little-endian order, in 4-byte chunks.
    # could just copymem?
    for i in 4..11:
        littleEndian32(c.initial_state[i].addr, c.key[(i-4) shl 2].unsafeAddr)
    # Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
    # word is enough for 256 gigabytes of data.
    c.initial_state[12] = c.counter
    # Words 13-15 are a nonce, which should not be repeated for the same
    # key.  The 13th word is the first 32 bits of the input nonce taken
    # as a little-endian integer, while the 15th word is the last 32
    # bits.
    for i in 13..15:
        littleEndian32(c.initial_state[i].addr, c.nonce[(i-13) shl 2].unsafeAddr)

proc chachca20_rounds*(state: var State) =
    for _ in 1..10:
        state.chacha20_innerblock()

proc chacha20_add_serialize*(
    c: var ChaCha,
    destination_block: var Block) =
    # peform add and serialization 16->64
    var n: uint32
    for i in 0..c.initial_state.high:
        n = c.state[i] + c.initial_state[i]
        littleEndian32(destination_block[i shl 2].addr, n.addr)


proc chacha20_block*(
    c: var ChaCha,
    destination_block: var Block) =
    c.chacha20_init_state()
    c.state = c.initial_state
    # ChaCha20 runs 20 rounds, alternating between "column rounds" and
    # "diagonal rounds". 
    c.state.chachca20_rounds()
    # At the end of 20 rounds (or 10 iterations of the above list), we add
    # the original input words to the output words, and serialize the
    # result by sequencing the words one-by-one in little-endian order.
    # 
    # Note: "addition" in the above paragraph is done modulo 2^32.  In some
    # machine languages, this is called carryless addition on a 32-bit
    # word.
    chacha20_add_serialize(c , destination_block)



# encrypt and decrypt block
proc chacha20_xor*(
    c: var ChaCha,
    source: openArray[byte],
    destination: var openArray[byte]
    ) =
    var 
        key_stream: Block
        idx = 0
    #  could reduce cycles?
    for j in countup(0, (destination.len() div 64)-1, 64):
        chacha20_block(c, key_stream)
        c.counter.inc()
        for i in 0..63:
            destination[idx] = source[idx] xor key_stream[i]
            idx.inc()
    if destination.len() mod 64 != 0:
        chacha20_block(c, key_stream)
        c.counter.inc()
        for i in 0..(destination.high - (destination.len() div 64)*64):
            destination[idx] = source[idx] xor key_stream[i]
            idx.inc()
    # for j in 0..((destination.len div 64)-1):
    #     chacha20_block(c, key_stream)

