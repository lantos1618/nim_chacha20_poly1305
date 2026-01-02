# Vulnerability proof-of-concept tests

import unittest
import nim_chacha20_poly1305/[common, chacha20, chacha20_poly1305]

suite "vulnerabilities":
  test "CRITICAL_keystream_reuse_due_to_bad_counter_update":
    echo "\n[!] Testing for Keystream Reuse Vulnerability..."

    var key: Key
    var nonce: Nonce
    # Zero key/nonce for deterministic test

    # Message 1: Needs 2 blocks (1 block for OTK, 1 for payload)
    # Payload is 64 bytes ("A" * 64)
    var msg1 = newSeq[byte](64)
    for i in 0..63: msg1[i] = 'A'.byte

    var msg2 = newSeq[byte](64)
    for i in 0..63: msg2[i] = 'B'.byte

    var cipher1 = newSeq[byte](64)
    var cipher2 = newSeq[byte](64)
    var tag1, tag2: Tag

    var counter: Counter = 0

    # 1. Encrypt Message 1
    # Internal behavior:
    #   - Generates OTK using Block(0)
    #   - Increments internal counter to 1
    #   - Encrypts Payload using Block(1)
    #   - BUG: User 'counter' var is only incremented to 1 (should be 2)
    chacha20_aead_poly1305_encrypt(key, nonce, counter, @[], msg1, cipher1, tag1)

    echo "Counter after Msg1 (Length 64): ", counter

    # Counter should be 2 (1 for OTK + 1 for 64-byte payload)
    # If it's only 1, we have the vulnerability
    let expected_counter = 1'u32 + uint32((msg1.len + 63) div 64)

    if counter != expected_counter:
      echo "[!] Counter is ", counter, " but should be ", expected_counter
      echo "[!!!] VULNERABILITY: Counter not properly updated!"

      # 2. Encrypt Message 2 - will reuse keystream
      chacha20_aead_poly1305_encrypt(key, nonce, counter, @[], msg2, cipher2, tag2)

      # 3. Prove Collision - reconstruct Block(1) from Msg1
      var block1_reconstructed = newSeq[byte](64)
      for i in 0..63:
        block1_reconstructed[i] = cipher1[i] xor 'A'.byte

      # OTK for Msg2 is first 32 bytes of Block(1)
      var otk2_reconstructed: Key
      for i in 0..31:
        otk2_reconstructed[i] = block1_reconstructed[i]

      # Generate actual OTK for counter=1
      var true_otk2 = chacha20_poly1305_key_gen(key, nonce, 1)

      if otk2_reconstructed == true_otk2:
        echo "[!!!] VULNERABILITY CONFIRMED: Message 1 Keystream == Message 2 OTK"
        echo "An attacker can derive the Poly1305 key for Message 2 from Message 1."
        fail()
      else:
        echo "[?] Counter bug exists but collision not demonstrated in this test"
        fail()
    else:
      echo "[OK] Counter properly updated to ", counter
