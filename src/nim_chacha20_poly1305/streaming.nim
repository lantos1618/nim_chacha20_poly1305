# Streaming ChaCha20-Poly1305 Implementation
#
# Note: Streaming decryption releases plaintext before tag verification.
# Use streamDecrypt() which buffers and verifies first, or implement
# chunked authentication for large files.

import common, chacha20, poly1305, helpers

# Streaming cipher state with proper isolation
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

# Safe streaming cipher initialization
proc initStreamCipher*(key: Key, nonce: Nonce, counter: Counter = 0): StreamCipher =
    # Input validation
    if key.len != 32:
        raise newException(ValueError, "Key must be exactly 32 bytes")
    if nonce.len != 12:
        raise newException(ValueError, "Nonce must be exactly 12 bytes")
    
    result.chacha.key = key
    result.chacha.nonce = nonce
    result.chacha.counter = counter
    result.buffer_pos = 64  # Force initial keystream generation
    result.initialized = true
    result.finalized = false

# Streaming encryption/decryption with proper state management
proc update*(cipher: var StreamCipher, input: openArray[byte], output: var openArray[byte]) =
    # State validation
    if not cipher.initialized:
        raise newException(ValueError, "Cipher not initialized")
    if cipher.finalized:
        raise newException(ValueError, "Cipher already finalized")
    if input.len != output.len:
        raise newException(ValueError, "Input and output lengths must match")
    
    if input.len == 0:
        return  # Nothing to process
    
    # Process input byte by byte using buffered keystream
    for i in 0..<input.len:
        # Generate new keystream block if needed
        if cipher.buffer_pos >= 64:
            # Check for counter overflow before generating new block
            # RFC 7539: "If the counter overflows, the program MUST stop"
            if cipher.chacha.counter == high(uint32):
                raise newException(ValueError, "Counter overflow - maximum message size exceeded (256 GB)")
            cipher.chacha.chacha20_block(cipher.keystream_buffer)
            cipher.chacha.counter.inc()
            cipher.buffer_pos = 0

        # XOR with keystream
        output[i] = input[i] xor cipher.keystream_buffer[cipher.buffer_pos]
        cipher.buffer_pos.inc()

# Finalize streaming cipher and clear sensitive state
proc finalize*(cipher: var StreamCipher) =
    if cipher.initialized:
        secureZeroArray(cipher.chacha.key)
        secureZeroArray(cipher.chacha.state)
        secureZeroArray(cipher.chacha.initial_state)
        secureZero(cipher.keystream_buffer)
        cipher.finalized = true

# Safe streaming MAC initialization
proc initStreamMAC*(key: Key): StreamMAC =
    if key.len != 32:
        raise newException(ValueError, "Key must be exactly 32 bytes")
    
    result.poly.poly1305_init(key)
    result.initialized = true  
    result.finalized = false

# Streaming MAC update with validation
proc update*(mac: var StreamMAC, data: openArray[byte]) =
    if not mac.initialized:
        raise newException(ValueError, "MAC not initialized")
    if mac.finalized:
        raise newException(ValueError, "MAC already finalized")

    if data.len > 0:
        # Use the fixed poly1305_update which now correctly processes blocks without finalizing
        mac.poly.poly1305_update(data)

# MAC finalization with secure cleanup
proc finalize*(mac: var StreamMAC): Tag =
    if not mac.initialized:
        raise newException(ValueError, "MAC not initialized")
    if mac.finalized:
        raise newException(ValueError, "MAC already finalized")

    # Complete MAC computation using the fixed poly1305_final function
    result = mac.poly.poly1305_final()

    mac.finalized = true

    # Clear sensitive state
    mac.poly.poly1305_finalize()

# INTERNAL: Core streaming AEAD initialization
proc initStreamAEADImpl(key: Key, nonce: Nonce, encrypt: bool, counter: Counter): StreamAEAD =
    if key.len != 32:
        raise newException(ValueError, "Key must be exactly 32 bytes")
    if nonce.len != 12:
        raise newException(ValueError, "Nonce must be exactly 12 bytes")

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

    # Clear temporary key block and chacha state
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

    # Clear OTK from stack
    secureZero(otk)

# DEPRECATED: Use initStreamAEADEncrypt() for encryption or streamDecrypt() for decryption.
# Using encrypt=false with manual streaming releases UNVERIFIED plaintext,
# violating the Cryptographic Doom Principle. Use streamDecrypt() for safe decryption.
proc initStreamAEAD*(key: Key, nonce: Nonce, encrypt: bool, counter: Counter = 0): StreamAEAD
    {.deprecated: "Use initStreamAEADEncrypt() for encryption or streamDecrypt() for safe decryption".} =
    initStreamAEADImpl(key, nonce, encrypt, counter)

# Safe streaming encryption initialization
proc initStreamAEADEncrypt*(key: Key, nonce: Nonce, counter: Counter = 0): StreamAEAD =
    initStreamAEADImpl(key, nonce, encrypt = true, counter)

# Streaming AEAD authenticated data processing
proc updateAuthData*(aead: var StreamAEAD, auth_data: openArray[byte]) =
    if not aead.initialized:
        raise newException(ValueError, "AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "AEAD already finalized")
    if aead.auth_data_processed:
        raise newException(ValueError, "Auth data phase already completed")
    
    if auth_data.len > 0:
        aead.mac.update(auth_data)
        aead.auth_data_len += auth_data.len.uint64

# Complete authenticated data phase
proc finalizeAuthData*(aead: var StreamAEAD) =
    if not aead.initialized:
        raise newException(ValueError, "AEAD not initialized") 
    if aead.auth_data_processed:
        return  # Already processed
    
    # Add padding for auth data to 16-byte boundary
    let pad_len = if aead.auth_data_len mod 16 == 0: 0 else: int(16 - (aead.auth_data_len mod 16))
    if pad_len > 0:
        let auth_pad = newSeq[byte](pad_len)  # Zero padding
        aead.mac.update(auth_pad)
    
    aead.auth_data_processed = true

# INTERNAL: Streaming AEAD cipher data processing (private - use streamEncrypt/streamDecrypt)
# In decrypt mode, output contains UNVERIFIED plaintext until verify() is called.
# This function is intentionally private to prevent misuse.
proc updateCipherData(aead: var StreamAEAD, input: openArray[byte], output: var openArray[byte]) =
    if not aead.initialized:
        raise newException(ValueError, "AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "AEAD already finalized")

    # Emit compile-time warning for decrypt mode usage
    when defined(warnStreamingDecrypt):
        if not aead.encrypt_mode:
            {.warning: "updateCipherData in decrypt mode releases UNVERIFIED plaintext - use streamDecrypt() for safety".}
    
    # Ensure auth data phase is complete
    aead.finalizeAuthData()
    
    if input.len != output.len:
        raise newException(ValueError, "Input and output lengths must match")
    
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

# AEAD finalization with length validation
proc finalize*(aead: var StreamAEAD): Tag =
    if not aead.initialized:
        raise newException(ValueError, "AEAD not initialized")
    if aead.finalized:
        raise newException(ValueError, "AEAD already finalized")
    
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

    # Clear length block and cipher state
    secureZero(length_block)
    aead.cipher.finalize()

# Verify MAC in constant time for streaming AEAD
proc verify*(aead: var StreamAEAD, expected_tag: Tag): bool =
    if not aead.finalized:
        let computed_tag = aead.finalize()
        result = poly1305_verify(expected_tag, computed_tag)
    else:
        raise newException(ValueError, "AEAD already finalized")

# Complete streaming encryption in one call
proc streamEncrypt*(key: Key, nonce: Nonce,
                    auth_data: openArray[byte],
                    plaintext: openArray[byte],
                    ciphertext: var openArray[byte],
                    counter: Counter = 0): Tag =
    if plaintext.len != ciphertext.len:
        raise newException(ValueError, "Plaintext and ciphertext lengths must match")

    var aead = initStreamAEADImpl(key, nonce, encrypt = true, counter)
    
    if auth_data.len > 0:
        aead.updateAuthData(auth_data)
    aead.finalizeAuthData()
    
    if plaintext.len > 0:
        aead.updateCipherData(plaintext, ciphertext)
    
    result = aead.finalize()

# Complete streaming decryption with verification
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
        raise newException(ValueError, "Ciphertext and plaintext lengths must match")

    # Decrypt to internal buffer first to prevent unverified plaintext exposure
    # This adds memory overhead but is required for secure one-shot decryption
    var tempBuffer = newSeq[byte](ciphertext.len)

    var aead = initStreamAEADImpl(key, nonce, encrypt = false, counter)

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

    # Always clear the temporary buffer
    secureZero(tempBuffer)
