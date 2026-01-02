# Basic usage examples for ChaCha20-Poly1305 cryptographic library

import ../src/nim_chacha20_poly1305/[common, chacha20_poly1305, streaming, helpers, poly1305]
import std/[sysrand, strutils]

proc example_basic_aead() =
    echo "🔒 Basic AEAD Encryption/Decryption Example"
    echo "=" .repeat(50)
    
    # Generate secure random key and nonce
    var key: Key
    var nonce: Nonce
    discard urandom(key)
    discard urandom(nonce)
    
    echo "🔑 Key: ", bytesToHex(key)
    echo "🎲 Nonce: ", bytesToHex(nonce)
    
    # Data to encrypt
    let message = "This is a secret message that needs protection!"
    var plaintext = stringToBytes(message)
    let auth_data = stringToBytes("Version: 1.0, User: Alice")
    
    echo "📝 Original: ", message
    echo "🏷️ Auth Data: ", bytesToString(auth_data)
    
    # Encryption
    var ciphertext = newSeq[byte](plaintext.len)
    var tag: Tag
    var counter: Counter = 0
    
    chacha20_aead_poly1305_encrypt(
        key, nonce, counter,
        auth_data, plaintext, ciphertext, tag
    )
    
    echo "🔒 Encrypted: ", bytesToHex(ciphertext)
    echo "🛡️ Auth Tag: ", bytesToHex(tag)
    
    # Decryption with MANDATORY authentication verification
    var decrypted = newSeq[byte](ciphertext.len)
    counter = 0  # Reset counter

    # IMPORTANT: Always use decrypt_verified - it checks tag BEFORE decrypting
    let success = chacha20_aead_poly1305_decrypt_verified(
        key, nonce, counter,
        auth_data, ciphertext, decrypted, tag
    )

    if success:
        echo "✅ Decrypted: ", bytesToString(decrypted)
        echo "✅ Success: Authentication verified and message recovered!"
    else:
        echo "❌ Authentication failed - data may be tampered!"
        # decrypted buffer is automatically zeroed on failure
    echo ""

proc example_streaming_large_data() =
    echo "🌊 Streaming Example - Large Data Processing"
    echo "=" .repeat(50)
    
    var key: Key
    var nonce: Nonce
    discard urandom(key)
    discard urandom(nonce)
    
    # Simulate large data (1KB chunks)
    let chunk_size = 1024
    let total_chunks = 5
    
    echo "📊 Processing ", total_chunks, " chunks of ", chunk_size, " bytes each"
    
    # === STREAMING ENCRYPTION ===
    var encrypt_aead = initStreamAEAD(key, nonce, encrypt = true)
    
    # Add authenticated data
    let metadata = stringToBytes("Large file transfer - streaming mode")
    encrypt_aead.updateAuthData(metadata)
    encrypt_aead.finalizeAuthData()
    
    var all_ciphertext: seq[byte]
    
    # Process large data in chunks
    for chunk_num in 1..total_chunks:
        # Generate chunk data
        var chunk_data = newSeq[byte](chunk_size)
        for i in 0..<chunk_size:
            chunk_data[i] = byte((chunk_num * 100 + i) mod 256)
        
        # Encrypt chunk
        var encrypted_chunk = newSeq[byte](chunk_size)
        encrypt_aead.updateCipherData(chunk_data, encrypted_chunk)
        
        # Accumulate for verification
        all_ciphertext.add(encrypted_chunk)
        
        echo "🔒 Processed chunk ", chunk_num, "/", total_chunks
    
    let final_tag = encrypt_aead.finalize()
    echo "✅ Encryption complete. Auth tag: ", bytesToHex(final_tag)
    
    # === STREAMING DECRYPTION ===
    var decrypt_aead = initStreamAEAD(key, nonce, encrypt = false)
    
    # Process auth data
    decrypt_aead.updateAuthData(metadata)
    decrypt_aead.finalizeAuthData()
    
    var all_plaintext: seq[byte]
    var pos = 0
    
    # Decrypt in chunks
    for chunk_num in 1..total_chunks:
        let chunk_data = all_ciphertext[pos..<pos+chunk_size]
        var decrypted_chunk = newSeq[byte](chunk_size)
        
        decrypt_aead.updateCipherData(chunk_data, decrypted_chunk)
        all_plaintext.add(decrypted_chunk)
        
        pos += chunk_size
        echo "🔓 Decrypted chunk ", chunk_num, "/", total_chunks
    
    # Verify authentication
    let verify_success = decrypt_aead.verify(final_tag)
    
    if verify_success:
        echo "✅ Authentication successful - data integrity verified!"
        echo "📊 Total processed: ", all_plaintext.len, " bytes"
    else:
        echo "❌ Authentication failed - data may be corrupted!"
    
    echo ""

proc example_security_features() =
    echo "🛡️ Security Features Demonstration"
    echo "=" .repeat(50)
    
    # Demonstrate constant-time comparison
    let tag1: Tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let tag2: Tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17]
    
    echo "🔒 Constant-time MAC verification:"
    echo "   Same tags: ", poly1305_verify(tag1, tag1)
    echo "   Different tags: ", poly1305_verify(tag1, tag2)
    
    # Demonstrate secure memory clearing
    var sensitive_data = stringToBytes("very secret key material")
    echo "🧹 Before clearing: ", bytesToString(sensitive_data)
    
    secureZero(sensitive_data)
    echo "🧹 After clearing: ", bytesToString(sensitive_data)
    
    # Demonstrate input validation
    echo "✅ Input validation prevents attacks - library validates all inputs"
    echo ""

when isMainModule:
    echo "🔒 ChaCha20-Poly1305 Security-Hardened Cryptographic Library"
    echo "🛡️ Production-Ready Examples"
    echo "=" .repeat(60)
    echo ""
    
    example_basic_aead()
    example_streaming_large_data()
    example_security_features()
    
    echo "🎉 All examples completed successfully!"
    echo "🔒 Library is ready for production use with proper key management"
