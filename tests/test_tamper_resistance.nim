import unittest
import nim_chacha20_poly1305/[common, streaming]

suite "tamper_resistance":
    test "streamDecrypt_rejects_tampered_ciphertext":
        var key: Key
        var nonce: Nonce
        let auth_data: seq[byte] = @[]

        # 1. Setup valid encryption
        let original_msg = cast[seq[byte]]("Transfer $100 to Alice")
        var ciphertext = newSeq[byte](original_msg.len)

        # Encrypt valid message using safe API
        let valid_tag = streamEncrypt(key, nonce, auth_data, original_msg, ciphertext)

        # 2. ATTACK: Tamper with ciphertext in transit
        var tampered_ciphertext = ciphertext
        let target_idx = original_msg.len - 5  # Position of 'A' in "Alice"
        tampered_ciphertext[target_idx] = tampered_ciphertext[target_idx] xor 12

        # 3. Attempt decryption with tampered data
        var output_buffer = newSeq[byte](original_msg.len)

        # Fill buffer with marker bytes to verify it gets zeroed on failure
        for i in 0..<output_buffer.len:
            output_buffer[i] = 0xAA

        # Safe API: streamDecrypt verifies BEFORE releasing plaintext
        let verified = streamDecrypt(key, nonce, auth_data,
                                      tampered_ciphertext, output_buffer, valid_tag)

        # 4. Verification must fail
        check(verified == false)

        # 5. Output buffer must be zeroed (no unverified plaintext leaked)
        var all_zeroed = true
        for b in output_buffer:
            if b != 0:
                all_zeroed = false
                break

        check(all_zeroed == true)
        echo "PASS: Tampered ciphertext rejected, output buffer securely zeroed"

    test "streamDecrypt_accepts_valid_ciphertext":
        var key: Key
        var nonce: Nonce
        let auth_data: seq[byte] = @[]

        let original_msg = cast[seq[byte]]("Transfer $100 to Alice")
        var ciphertext = newSeq[byte](original_msg.len)

        let valid_tag = streamEncrypt(key, nonce, auth_data, original_msg, ciphertext)

        var output_buffer = newSeq[byte](original_msg.len)
        let verified = streamDecrypt(key, nonce, auth_data,
                                      ciphertext, output_buffer, valid_tag)

        check(verified == true)
        check(output_buffer == original_msg)
        echo "PASS: Valid ciphertext accepted and decrypted correctly"

    test "streamDecrypt_rejects_wrong_tag":
        var key: Key
        var nonce: Nonce
        let auth_data: seq[byte] = @[]

        let original_msg = cast[seq[byte]]("Secret message")
        var ciphertext = newSeq[byte](original_msg.len)

        discard streamEncrypt(key, nonce, auth_data, original_msg, ciphertext)

        # Create a fake tag
        var fake_tag: Tag
        for i in 0..<16:
            fake_tag[i] = byte(i)

        var output_buffer = newSeq[byte](original_msg.len)
        for i in 0..<output_buffer.len:
            output_buffer[i] = 0xBB

        let verified = streamDecrypt(key, nonce, auth_data,
                                      ciphertext, output_buffer, fake_tag)

        check(verified == false)

        # Verify buffer is zeroed
        for b in output_buffer:
            check(b == 0)

        echo "PASS: Wrong tag rejected, output buffer securely zeroed"

    test "streamDecrypt_rejects_modified_auth_data":
        var key: Key
        var nonce: Nonce
        let auth_data = cast[seq[byte]]("header=valid")

        let original_msg = cast[seq[byte]]("Payload data")
        var ciphertext = newSeq[byte](original_msg.len)

        let valid_tag = streamEncrypt(key, nonce, auth_data, original_msg, ciphertext)

        # Attack: use different auth data during decryption
        let tampered_auth = cast[seq[byte]]("header=admin")

        var output_buffer = newSeq[byte](original_msg.len)
        let verified = streamDecrypt(key, nonce, tampered_auth,
                                      ciphertext, output_buffer, valid_tag)

        check(verified == false)

        for b in output_buffer:
            check(b == 0)

        echo "PASS: Modified auth data rejected, output buffer securely zeroed"
