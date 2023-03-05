// Copyright (C) 2023 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the TESTS_LICENSE file.

import expect show *
import mfrc522.crypto1

main:
  test_crypto1_cipher
  test_crypto1_prng
  test_mifare_classic_authentication
  test_parity_encryption

test_crypto1_cipher:
  cipher := crypto1.Crypto1
  expect_equals 0 cipher.state

  cipher.set_key #[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
  expect_equals #[0x01, 0x00, 0x00, 0x00, 0x00, 0x00] (cipher.state --as_bytes)
  // The least significant bit of the first byte of the
  // key is in the most-significant bit of the state.
  expect_equals 0x8000_00000000 cipher.state

  // Shifting moves the bit out.
  cipher.shift
  expect_equals 1 cipher.state

  cipher.set_key #[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
  expect_equals #[0x01, 0x00, 0x00, 0x00, 0x00, 0x00] (cipher.state --as_bytes)
  // Shifting with an input, xores the shifted in bit with the input.
  cipher.shift 1
  expect_equals 0 cipher.state

  cipher.set_key #[0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
  expect_equals #[0x00, 0x00, 0x00, 0x00, 0x00, 0x80] (cipher.state --as_bytes)
  // The most significant bit of the last byte of the
  // key is in the least-significant bit of the state.
  expect_equals 1 cipher.state
  // When shifting in a bit, none of the other bits change.
  cipher.shift
  expect_equals 0b10 cipher.state

  cipher.set_key #[0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
  expect_equals #[0x00, 0x00, 0x00, 0x00, 0x00, 0x80] (cipher.state --as_bytes)
  // Shifting with an input, xores the shifted in bit with the input.
  cipher.shift 1
  expect_equals 0b11 cipher.state

  cipher.set_key #[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
  expect_equals #[0x01, 0x02, 0x03, 0x04, 0x05, 0x06] (cipher.state --as_bytes)
  expect_equals 0x8040c020a060 cipher.state

  cipher.shift 0xFF --bit_count=16
  expect_equals 0xc020a0602ad5 cipher.state

  cipher.set_key #[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
  crypted := cipher.crypt #[0x00, 0x00]
  expect_equals #[0xb9, 0xc4] crypted
  expect_equals 0xc020a060d065 cipher.state

  cipher.set_key #[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
  // Feeding in a plaintext of 0x8000 when crypting 16 bits
  // will only affect the least significant bit of the state.
  crypted = cipher.crypt --feed_plain=0x8000 #[0x00, 0x00]
  expect_equals #[0xb9, 0xc4] crypted
  expect_equals 0xc020a060d064 cipher.state

  cipher.set_key #[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
  // Feeding in crypted text will be affected by the
  // state, so even the first bits will change.
  crypted = cipher.crypt
      --feed_crypted=0x1234
      #[0x00, 0x00]
  expect_equals #[0x91, 0xa0] crypted
  expect_equals 0xc020a06073aa cipher.state

  key := #[0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6]
  plaintext := #[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
  ciphertext := #[0x9b, 0xe2, 0x26, 0xb7, 0xd9, 0xf3, 0x93, 0x19]
  cipher1 := crypto1.Crypto1
  cipher1.set_key key
  expect_equals #[0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6] (cipher1.state --as_bytes)
  expect_equals ciphertext (cipher1.crypt plaintext)

  cipher2 := crypto1.Crypto1
  cipher2.set_key key
  expect_equals plaintext (cipher2.crypt ciphertext)

  // Both ciphers are in the same state.
  expect_equals
    cipher1.crypt #[1, 2, 3, 4, 5, 6, 7, 8]
    cipher2.crypt #[1, 2, 3, 4, 5, 6, 7, 8]

test_crypto1_prng:
  prng := crypto1.Crypto1Prng
  expect_equals 0 prng.state

  prng.set_state 1
  expect_equals 1 prng.state
  // Shifting inserts bit from the right.
  prng.shift
  expect_equals 0b10 prng.state
  // The first tap is at bit 10. (0x400
  // Shifting for 7 more times will only insert 0s.
  prng.shift 9
  expect_equals 0b100_00000000 prng.state
  // Now a 1-bit is picked up by a tap.
  prng.shift
  expect_equals 0b1000_00000001 prng.state

  expect_equals #[0x00, 0x00, 0x10, 0x80] (prng.state --as_bytes)

  // Some examples, taken from real-world communications.
  initial_state := #[0xe7, 0x6a, 0x55, 0x36]
  state64 := #[0xbe, 0xd9, 0x2b, 0x0a]
  state96 := #[0xb5, 0x41, 0xe3, 0xe3]
  prng.set_state --bytes=initial_state
  expect_equals initial_state (prng.state --as_bytes)
  prng.shift 64
  expect_equals state64 (prng.state --as_bytes)
  prng.shift 32
  expect_equals state96 (prng.state --as_bytes)

  initial_state = #[0x3c, 0xc8, 0x75, 0xad]
  state64 = #[0x7f, 0xb0, 0xec, 0x6f]
  state96 = #[0x95, 0x32, 0xf6, 0xc9]
  prng.set_state --bytes=initial_state
  expect_equals initial_state (prng.state --as_bytes)
  prng.shift 64
  expect_equals state64 (prng.state --as_bytes)
  prng.shift 32
  expect_equals state96 (prng.state --as_bytes)

test_mifare_classic_authentication:
  // Compare to the trace of [0], Appendix C.
  // [0]: https://ora.ox.ac.uk/objects/uuid:8e52bcfe-5ab5-40b8-b1f4-6b11fd0e67f2/download_file?file_format=application%2Fpdf&safe_filename=12-15.pdf&type_of_work=Working+paper
  uuid := #[0xcd, 0x76, 0x92, 0x74]
  key := #[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
  reader := crypto1.MifareCryptoReader --uid=uuid
  writer := crypto1.MifareCryptoWriter --uid=uuid

  reader.start_authentication --key=key
  encrypted_auth_request := reader.encrypt #[0x60, 0x3c]
  // This is not a nested authentication. So the request isn't encrypted.
  expect_equals #[0x60, 0x3c] (encrypted_auth_request.to_non_raw --no-check_parity).bytes

  writer.start_authentication --key=key
  nonce_tag := #[0x0e, 0x61, 0x64, 0xd6]
  encrypted_nonce_response := writer.encrypt nonce_tag
  // This isn't a nested authentication, so the nonce isn't encrypted.
  expect_equals nonce_tag (encrypted_nonce_response.to_non_raw --no-check_parity).bytes
  decrypted_nonce_response := reader.decrypt encrypted_nonce_response
  expect_equals nonce_tag decrypted_nonce_response

  // The reader generates the challenge response.
  nonce_reader := #[0x15, 0x45, 0x90, 0xa8]
  challenge_response := reader.generate_challenge_response
      --nonce_tag=decrypted_nonce_response
      --nonce_reader=nonce_reader
  expect_equals #[0x15, 0x45, 0x90, 0xa8, 0x4f, 0x4e, 0x67, 0x4e] challenge_response
  encrypted_challenge_response := reader.encrypt challenge_response
  expect_equals
      #[0x78, 0x5a, 0x41, 0x80, 0x50, 0x04, 0x8f, 0x22]
      (encrypted_challenge_response.to_non_raw --no-check_parity).bytes
  decrypted_challenge_response := writer.decrypt encrypted_challenge_response
  expect_equals challenge_response decrypted_challenge_response

  final_message := writer.compute_final_message decrypted_challenge_response
  expect_equals #[0x41, 0x3e, 0xeb, 0xcf] final_message
  encrypted_final_message := writer.encrypt final_message
  expect_equals
      #[0xce, 0xca, 0x0d, 0x83]
      (encrypted_final_message.to_non_raw --no-check_parity).bytes
  decrypted_final_message := reader.decrypt encrypted_final_message
  expect_equals final_message decrypted_final_message

  succeeded := reader.compare_tag_response decrypted_final_message
  expect succeeded

  // Communication can proceed normally now.
  encrypted_command := reader.encrypt #[0x30, 0x3f, 0x76, 0x61]
  expect_equals
      #[0x69, 0xac, 0x4f, 0x02]
      (encrypted_command.to_non_raw --no-check_parity).bytes
  decrypted_command := writer.decrypt encrypted_command
  expect_equals #[0x30, 0x3f, 0x76, 0x61] decrypted_command

  // Now do a nested authentication. Still from the same trace.
  reader.start_authentication --key=key
  encrypted_auth_request = reader.encrypt #[0x60, 0x34]
  // Since we haven't done all the steps as in the original trace, the encrypted
  // auth request is different, than the one in the trace.

  // The tag receives the request.
  decrypted_auth_request := writer.decrypt encrypted_auth_request
  expect_equals #[0x60, 0x34] decrypted_auth_request

  writer.start_authentication --key=key

  nonce_tag = #[0xdc, 0xfc, 0x96, 0x2b]
  encrypted_nonce_response = writer.encrypt nonce_tag
  // Since this is a nested authentication, the nonce is already encrypted.
  expect_equals
      #[0x23, 0x23, 0x6e, 0xf4]
      (encrypted_nonce_response.to_non_raw --no-check_parity).bytes
  decrypted_nonce_response = reader.decrypt encrypted_nonce_response
  expect_equals nonce_tag decrypted_nonce_response

  // The reader generates the challenge response.
  nonce_reader = #[0xee, 0x08, 0xb0, 0x0a]
  challenge_response = reader.generate_challenge_response
      --nonce_tag=decrypted_nonce_response
      --nonce_reader=nonce_reader
  expect_equals #[0xee, 0x08, 0xb0, 0x0a, 0xf6, 0x01, 0xba, 0x11] challenge_response
  encrypted_challenge_response = reader.encrypt challenge_response
  expect_equals
      #[0x1a, 0xb9, 0xef, 0x7b, 0xc5, 0xc3, 0x51, 0x57]
      (encrypted_challenge_response.to_non_raw --no-check_parity).bytes
  decrypted_challenge_response = writer.decrypt encrypted_challenge_response
  expect_equals challenge_response decrypted_challenge_response

  final_message = writer.compute_final_message decrypted_challenge_response
  expect_equals #[0x6e, 0x27, 0x63, 0x93] final_message
  encrypted_final_message = writer.encrypt final_message
  expect_equals
      #[0x3e, 0x19, 0x48, 0xf4]
      (encrypted_final_message.to_non_raw --no-check_parity).bytes
  decrypted_final_message = reader.decrypt encrypted_final_message
  expect_equals final_message decrypted_final_message

  succeeded = reader.compare_tag_response decrypted_final_message
  expect succeeded

  // Communication can proceed normally now.
  encrypted_command = reader.encrypt #[0x30, 0x37, 0x3e, 0xed]
  expect_equals
      #[0xd6, 0x59, 0xb4, 0x73]
      (encrypted_command.to_non_raw --no-check_parity).bytes
  decrypted_command = writer.decrypt encrypted_command
  expect_equals #[0x30, 0x37, 0x3e, 0xed] decrypted_command

test_parity_encryption:
  // Compare to the trace of [0], Appendix C.
  // [0]: https://ora.ox.ac.uk/objects/uuid:8e52bcfe-5ab5-40b8-b1f4-6b11fd0e67f2/download_file?file_format=application%2Fpdf&safe_filename=12-15.pdf&type_of_work=Working+paper

  check_parity := : | plaintext/ByteArray ciphertext/ByteArray next_cipher_bit/int expected_inverted_parities/List |
    reader := crypto1.MifareCryptoReader --uid=#[0, 0, 0, 0]
    with_parity := reader.add_parity
        --plain=plaintext
        --cipher=ciphertext
        --current_crypto_bit=next_cipher_bit

    plaintext.size.repeat:
      bit := (it + 1) * 9 - 1
      byte_index := bit / 8
      bit_index := bit % 8
      ciphertext_parity := ciphertext[it].parity ^ 1  // Odd parity.
      // The parity that is actually sent.
      mifare_parity := (with_parity[byte_index] >> bit_index) & 1
      is_inverted := mifare_parity != ciphertext_parity
      expect_equals expected_inverted_parities[it] is_inverted

  // During the first authentication, when the PCD sends the a_r to the tag.
  plaintext := #[0x4f, 0x4e, 0x67, 0x4e]
  ciphertext := #[0x50, 0x04, 0x8f, 0x22]
  next_cipher_bit := (0x41 ^ 0xce) & 1
  // The exclamation points in the trace indicate that byte 1, 2, and 4 have
  // inverted parities.
  expected_inverted_parities := [true, true, false, true]
  check_parity.call plaintext ciphertext next_cipher_bit expected_inverted_parities

  // The first response when trying to read an inaccessible sector last entry on page 14.
  plaintext = #[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  ciphertext = #[0xbc, 0x2f, 0xbd, 0xb1, 0x75, 0x44]
  next_cipher_bit = (0xff ^ 0x3c) & 1
  expected_inverted_parities = [false, false, true, true, true, true]

  check_parity.call plaintext ciphertext next_cipher_bit expected_inverted_parities
