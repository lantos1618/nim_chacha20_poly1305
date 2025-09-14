# Basic streaming tests focusing on working functionality

import unittest
import nim_chacha20_poly1305/[common, streaming, helpers]

suite "streaming_basic":
    test "stream_cipher_functionality":
        # Test that streaming cipher works correctly
        var key: Key
        var nonce: Nonce
        for i in 0..31:
            key[i] = byte(i + 1)
        for i in 0..11:
            nonce[i] = byte(i + 1)
        
        var cipher = initStreamCipher(key, nonce, 0)
        
        let plaintext = cast[seq[byte]]("Hello, streaming world!")
        var ciphertext = newSeq[byte](plaintext.len)
        
        cipher.update(plaintext, ciphertext)
        
        # Verify encryption worked (ciphertext different from plaintext)
        check(ciphertext != plaintext)
        
        # Test decryption round-trip
        var cipher2 = initStreamCipher(key, nonce, 0)
        var decrypted = newSeq[byte](ciphertext.len)
        cipher2.update(ciphertext, decrypted)
        
        check(decrypted == plaintext)

    test "stream_cipher_chunked":
        # Test streaming cipher with chunked data
        var key: Key
        var nonce: Nonce
        for i in 0..31:
            key[i] = byte(i + 1)
        for i in 0..11:
            nonce[i] = byte(i + 1)
        
        let message = "This is a longer message that we'll encrypt in chunks to test streaming!"
        let plaintext = cast[seq[byte]](message)
        
        var cipher = initStreamCipher(key, nonce, 0)
        var ciphertext = newSeq[byte](plaintext.len)
        
        # Encrypt in 10-byte chunks
        let chunk_size = 10
        var pos = 0
        
        while pos < plaintext.len:
            let end_pos = min(pos + chunk_size, plaintext.len)
            let chunk_len = end_pos - pos
            
            var input_chunk = plaintext[pos..<end_pos]
            var output_chunk = newSeq[byte](chunk_len)
            
            cipher.update(input_chunk, output_chunk)
            
            # Copy to final ciphertext
            for i in 0..<chunk_len:
                ciphertext[pos + i] = output_chunk[i]
            
            pos = end_pos
        
        # Verify round-trip decryption
        var cipher2 = initStreamCipher(key, nonce, 0)
        var decrypted = newSeq[byte](ciphertext.len)
        
        # Decrypt in different chunk sizes to test flexibility
        pos = 0
        let decrypt_chunk_size = 7
        
        while pos < ciphertext.len:
            let end_pos = min(pos + decrypt_chunk_size, ciphertext.len)
            let chunk_len = end_pos - pos
            
            var input_chunk = ciphertext[pos..<end_pos] 
            var output_chunk = newSeq[byte](chunk_len)
            
            cipher2.update(input_chunk, output_chunk)
            
            # Copy to final plaintext
            for i in 0..<chunk_len:
                decrypted[pos + i] = output_chunk[i]
            
            pos = end_pos
        
        check(decrypted == plaintext)

    test "stream_security_validation":
        # Test security validations work
        var key: Key
        var nonce: Nonce
        for i in 0..31:
            key[i] = byte(i + 1)
        for i in 0..11:
            nonce[i] = byte(i + 1)
        
        var cipher = initStreamCipher(key, nonce, 0)
        
        # Test mismatched buffer lengths
        let input = @[byte(1), 2, 3, 4, 5]
        var output = newSeq[byte](3)  # Wrong size
        
        expect(ValueError):
            cipher.update(input, output)

    test "stream_init_validation":
        # Test that streaming functionality initializes correctly
        var key: Key
        var nonce: Nonce
        for i in 0..31:
            key[i] = byte(i + 1)
        for i in 0..11:
            nonce[i] = byte(i + 1)
        
        let cipher = initStreamCipher(key, nonce)
        check(cipher.initialized)
