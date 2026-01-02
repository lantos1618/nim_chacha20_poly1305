# Streaming ChaCha20-Poly1305 Implementation
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  🚨 CRITICAL SECURITY WARNING - READ BEFORE USING STREAMING DECRYPT 🚨  ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║                                                                          ║
# ║  The streaming decryption API (updateCipherData in decrypt mode)         ║
# ║  releases UNVERIFIED plaintext. This violates the Cryptographic          ║
# ║  Doom Principle and is INSECURE for untrusted data streams.              ║
# ║                                                                          ║
# ║  SAFE:                                                                   ║
# ║    ✅ streamDecrypt() - verifies tag, then returns plaintext             ║
# ║    ✅ Streaming ENCRYPTION (updateCipherData with encrypt=true)          ║
# ║    ✅ Buffer ALL output, call verify(), THEN process if true             ║
# ║                                                                          ║
# ║  UNSAFE (enables chosen-ciphertext attacks):                             ║
# ║    ❌ Processing updateCipherData() output before verify()               ║
# ║    ❌ Writing chunks to disk/network before final verification           ║
# ║    ❌ Parsing, executing, or allocating based on unverified data         ║
# ║                                                                          ║
# ║  For secure large-file decryption, use a CHUNKED protocol where          ║
# ║  each chunk has its own authentication tag (like libsodium secretstream) ║
# ║                                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import common, chacha20, poly1305, helpers

# SECURITY: Streaming cipher state with proper isolation
type
    StreamCipher* = object
        chacha: ChaCha
        keystream_buffer: Block
        buffer_pos: int
        initialized*: bool
        finalized*: bool

    StreamMAC* = object
        poly: Poly1305
        initialized*: bool
        finalized*: bool

    StreamAEAD* = object
        cipher: StreamCipher
        mac: StreamMAC  
        auth_data_processed: bool
        cipher_data_len: uint64
        auth_data_len: uint64
        encrypt_mode: bool
        initialized: bool
        finalized: bool

# SECURITY: Safe streaming cipher initialization
proc initStreamCipher*(key: Key, nonce: Nonce, counter: Counter = 0): StreamCipher =
    # SECURITY: Input validation
    if key.len != 32:
        raise newException(ValueError, "SECURITY: Key must be exactly 32 bytes")
    if nonce.len != 12:
        raise newException(ValueError, "SECURITY: Nonce must be exactly 12 bytes")
    
    result.chacha.key = key
    result.chacha.nonce = nonce
    result.chacha.counter = counter
    result.buffer_pos = 64  # Force initial keystream generation
    result.initialized = true
    result.finalized = false

# SECURITY: Streaming encryption/decryption with proper state management
proc update*(cipher: var StreamCipher, input: openArray[byte], output: var openArray[byte]) =
    # SECURITY: State validation
    if not cipher.initialized:
        raise newException(ValueError, "SECURITY: Cipher not initialized")
    if cipher.finalized:
        raise newException(ValueError, "SECURITY: Cipher already finalized")
    if input.len != output.len:
        raise newException(ValueError, "SECURITY: Input and output lengths must match")
    
    if input.len == 0:
        return  # Nothing to process
    
    # Process input byte by byte using buffered keystream
    for i in 0..<input.len:
        # Generate new keystream block if needed
        if cipher.buffer_pos >= 64:
            # SECURITY: Check for counter overflow before generating new block
            # RFC 7539: "If the counter overflows, the program MUST stop"
            if cipher.chacha.counter == high(uint32):
                raise newException(ValueError, "SECURITY: Counter overflow - maximum message size exceeded (256 GB)")
            cipher.chacha.chacha20_block(cipher.keystream_buffer)
            cipher.chacha.counter.inc()
            cipher.buffer_pos = 0

        # XOR with keystream
        output[i] = input[i] xor cipher.keystream_buffer[cipher.buffer_pos]
        cipher.buffer_pos.inc()

# SECURITY: Finalize streaming cipher and clear sensitive state
proc finalize*(cipher: var StreamCipher) =
    if cipher.initialized:
        secureZeroArray(cipher.chacha.key)
        secureZeroArray(cipher.chacha.state)
        secureZeroArray(cipher.chacha.initial_state)
        secureZero(cipher.keystream_buffer)
        cipher.finalized = true

# SECURITY: Safe streaming MAC initialization
proc initStreamMAC*(key: Key): StreamMAC =
    if key.len != 32:
        raise newException(ValueError, "SECURITY: Key must be exactly 32 bytes")
    
    result.poly.poly1305_init(key)
    result.initialized = true  
    result.finalized = false

# SECURITY: Streaming MAC update with validation
proc update*(mac: var StreamMAC, data: openArray[byte]) =
    if not mac.initialized:
        raise newException(ValueError, "SECURITY: MAC not initialized")
    if mac.finalized:
        raise newException(ValueError, "SECURITY: MAC already finalized")

    if data.len > 0:
        # Use the fixed poly1305_update which now correctly processes blocks without finalizing
        mac.poly.poly1305_update(data)

# SECURITY: MAC finalization with secure cleanup
proc finalize*(mac: var StreamMAC): Tag =
    if not mac.initialized:
        raise newException(ValueError, "SECURITY: MAC not initialized")
    if mac.finalized:
        raise newException(ValueError, "SECURITY: MAC already finalized")

    # Complete MAC computation using the fixed poly1305_final function
    result = mac.poly.poly1305_final()

    mac.finalized = true

    # SECURITY: Clear sensitive state
    mac.poly.poly1305_finalize()

# SECURITY: Streaming AEAD initialization with mode validation
proc initStreamAEAD*(key: Key, nonce: Nonce, encrypt: bool, counter: Counter = 0): StreamAEAD =
    if key.len != 32:
        raise newException(ValueError, "SECURITY: Key must be exactly 32 bytes")
    if nonce.len != 12:
        raise newException(ValueError, "SECURITY: Nonce must be exactly 12 bytes")
    
    # Generate OTK for Poly1305 using ChaCha20 at counter 0
    var otk_counter = counter
    result.cipher = initStreamCipher(key, nonce, otk_counter + 1)  # Data starts at counter+1
    
    # Generate one-time key for MAC
    var otk: Key
    var temp_chacha: ChaCha
    temp_chacha.key = key
    temp_chacha.nonce = nonce  
    temp_chacha.counter = otk_counter  # OTK at counter
    
    var key_block: Block
    temp_chacha.chacha20_block(key_block)
    copyMem(otk[0].addr, key_block[0].addr, 32)
    
    # SECURITY: Clear temporary key block and chacha state
    secureZero(key_block)
    secureZeroArray(temp_chacha.key)
    secureZeroArray(temp_chacha.state)
    secureZeroArray(temp_chacha.initial_state)

    result.mac = initStreamMAC(otk)
    result.encrypt_mode = encrypt
    result.auth_data_processed = false
    result.cipher_data_len = 0
    result.auth_data_len = 0
    result.initialized = true
    result.finalized = false

    # SECURITY: Clear OTK from stack
    secureZero(otk)

# SECURITY: Streaming AEAD authenticated data processing
proc updateAuthData*(aead: var StreamAEAD, auth_data: openArray[byte]) =
    if not aead.initialized:
        raise newException(ValueError, "SECURITY: AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "SECURITY: AEAD already finalized")
    if aead.auth_data_processed:
        raise newException(ValueError, "SECURITY: Auth data phase already completed")
    
    if auth_data.len > 0:
        aead.mac.update(auth_data)
        aead.auth_data_len += auth_data.len.uint64

# SECURITY: Complete authenticated data phase
proc finalizeAuthData*(aead: var StreamAEAD) =
    if not aead.initialized:
        raise newException(ValueError, "SECURITY: AEAD not initialized") 
    if aead.auth_data_processed:
        return  # Already processed
    
    # Add padding for auth data to 16-byte boundary
    let pad_len = if aead.auth_data_len mod 16 == 0: 0 else: int(16 - (aead.auth_data_len mod 16))
    if pad_len > 0:
        let auth_pad = newSeq[byte](pad_len)  # Zero padding
        aead.mac.update(auth_pad)
    
    aead.auth_data_processed = true

# SECURITY: Streaming AEAD cipher data processing
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║ 🚨 DECRYPT MODE WARNING: Output contains UNVERIFIED plaintext!        ║
# ║ DO NOT process, parse, or act on this data until verify() = true.    ║
# ║ For safe decryption, use streamDecrypt() instead.                    ║
# ╚═══════════════════════════════════════════════════════════════════════╝
proc updateCipherData*(aead: var StreamAEAD, input: openArray[byte], output: var openArray[byte]) =
    if not aead.initialized:
        raise newException(ValueError, "SECURITY: AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "SECURITY: AEAD already finalized")

    # Emit compile-time warning for decrypt mode usage
    when defined(warnStreamingDecrypt):
        if not aead.encrypt_mode:
            {.warning: "updateCipherData in decrypt mode releases UNVERIFIED plaintext - use streamDecrypt() for safety".}
    
    # Ensure auth data phase is complete
    aead.finalizeAuthData()
    
    if input.len != output.len:
        raise newException(ValueError, "SECURITY: Input and output lengths must match")
    
    if input.len == 0:
        return
    
    # Encrypt/decrypt the data
    aead.cipher.update(input, output)
    
    # Update MAC with cipher data (for encrypt mode) or input data (for decrypt mode)
    if aead.encrypt_mode:
        aead.mac.update(output)  # MAC the ciphertext
    else:
        aead.mac.update(input)   # MAC the ciphertext (which is input in decrypt mode)
    
    aead.cipher_data_len += input.len.uint64

# SECURITY: AEAD finalization with length validation
proc finalize*(aead: var StreamAEAD): Tag =
    if not aead.initialized:
        raise newException(ValueError, "SECURITY: AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "SECURITY: AEAD already finalized")
    
    # Ensure auth data is finalized
    aead.finalizeAuthData()
    
    # Add padding for cipher data to 16-byte boundary
    let cipher_pad_len = if aead.cipher_data_len mod 16 == 0: 0 else: int(16 - (aead.cipher_data_len mod 16))
    if cipher_pad_len > 0:
        let cipher_pad = newSeq[byte](cipher_pad_len)  # Zero padding
        aead.mac.update(cipher_pad)
    
    # Add lengths (auth_data_len || cipher_data_len) as little-endian uint64
    var length_block: array[16, byte]
    
    # Auth data length (little-endian uint64)
    for i in 0..7:
        length_block[i] = byte((aead.auth_data_len shr (i * 8)) and 0xff)
    
    # Cipher data length (little-endian uint64)  
    for i in 0..7:
        length_block[i + 8] = byte((aead.cipher_data_len shr (i * 8)) and 0xff)
    
    aead.mac.update(length_block)
    
    # Finalize MAC
    result = aead.mac.finalize()
    aead.finalized = true

    # SECURITY: Clear length block and cipher state
    secureZero(length_block)
    aead.cipher.finalize()

# SECURITY: Verify MAC in constant time for streaming AEAD
proc verify*(aead: var StreamAEAD, expected_tag: Tag): bool =
    if not aead.finalized:
        let computed_tag = aead.finalize()
        result = poly1305_verify(expected_tag, computed_tag)
    else:
        raise newException(ValueError, "SECURITY: AEAD already finalized")

# SECURITY: Complete streaming encryption in one call
proc streamEncrypt*(key: Key, nonce: Nonce, 
                    auth_data: openArray[byte],
                    plaintext: openArray[byte], 
                    ciphertext: var openArray[byte],
                    counter: Counter = 0): Tag =
    if plaintext.len != ciphertext.len:
        raise newException(ValueError, "SECURITY: Plaintext and ciphertext lengths must match")
    
    var aead = initStreamAEAD(key, nonce, encrypt = true, counter)
    
    if auth_data.len > 0:
        aead.updateAuthData(auth_data)
    aead.finalizeAuthData()
    
    if plaintext.len > 0:
        aead.updateCipherData(plaintext, ciphertext)
    
    result = aead.finalize()

# SECURITY: Complete streaming decryption with verification
# This function decrypts to an internal buffer first, then copies to output
# only after successful verification. This prevents TOCTOU vulnerabilities
# where unverified plaintext could be observed by other threads or persisted.
proc streamDecrypt*(key: Key, nonce: Nonce,
                    auth_data: openArray[byte],
                    ciphertext: openArray[byte],
                    plaintext: var openArray[byte],
                    tag: Tag,
                    counter: Counter = 0): bool =
    if ciphertext.len != plaintext.len:
        raise newException(ValueError, "SECURITY: Ciphertext and plaintext lengths must match")

    # SECURITY: Decrypt to internal buffer first to prevent unverified plaintext exposure
    # This adds memory overhead but is required for secure one-shot decryption
    var tempBuffer = newSeq[byte](ciphertext.len)

    var aead = initStreamAEAD(key, nonce, encrypt = false, counter)

    if auth_data.len > 0:
        aead.updateAuthData(auth_data)
    aead.finalizeAuthData()

    if ciphertext.len > 0:
        aead.updateCipherData(ciphertext, tempBuffer)

    result = aead.verify(tag)

    if result:
        # Verification succeeded - safe to copy plaintext to output
        for i in 0..<tempBuffer.len:
            plaintext[i] = tempBuffer[i]
    else:
        # Verification failed - zero the output buffer
        secureZero(plaintext)

    # SECURITY: Always clear the temporary buffer
    secureZero(tempBuffer)
