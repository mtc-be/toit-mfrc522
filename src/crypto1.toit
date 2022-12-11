// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

import binary show LITTLE_ENDIAN BIG_ENDIAN

/**
Crypto-1 cipher and PRNG.

# Cipher
Crypto-1 is a stream cipher used in Mifare Classic RFID cards.

At its core the cipher is a 48-bit linear feedback shift register (LFSR) with
  generating polynomial g(x) = x⁴⁸ + x⁴³ + x³⁹ + x³⁸ + x³⁶ + x³⁴ + x³³ + x³¹
  + x²⁹ + x²⁴ + x²³ + x²¹ + x¹⁹ + x¹³ + x⁹ + x⁷ + x⁶ + x⁵ + 1.

At any time k, the state sₖ of the LFSR is given by the 48-bit value
  sₖ=xₖxₖ₊₁…xₖ₊₄₇. At time k+1, the LFSR's state is updated to
  sₖ₊₁=xₖ₊₁xₖ₊₂…xₖ₊₄₈ by shifting the bits by one and adding
  xₖ₊₄₈ = xₖ⊕xₖ₊₅⊕xₖ₊₉⊕xₖ₊₁₀⊕xₖ₊₁₂⊕xₖ₊₁₄⊕xₖ₊₁₅⊕xₖ₊₁₇⊕xₖ₊₁₉⊕xₖ₊₂₄⊕xₖ₊₂₇⊕xₖ₊₂₉⊕xₖ₊₃₅⊕xₖ₊₃₉⊕xₖ₊₄₁⊕xₖ₊₄₂⊕xₖ₊₄₃.
During initialization r₊₄₈ is furthermore xored with input bits. See below in the Mifare
  authentication section.

Note that xₖ₊₄₈ is fundamentally a parity check on a subset of the bits xₖ…xₖ₋₄₇ (called "taps").
  Representing the state sₖ as a 48-bit integer (with xₖ being the most significant bit), the
  bit xₖ₊₄₈ (shifted in at the right) can be computed as the parity of
  sₖ & 0b100001000110101101010000110101000001000101110000 = sₖ & 0x846B50D41170

For encryption, the LFSR state is filtered through a function f, defined as
  f(x₀x₁…x₄₇) = f_c(v1, v2, v3, v4, v5), where
  v1 = f_b(x₉, x₁₁, x₁₃, x₁₅),
  v2 = f_a(x₁₇, x₁₉, x₂₁, x₂₃),
  v3 = f_a(x₂₅, x₂₇, x₂₉, x₃₁),
  v4 = f_b(x₃₃, x₃₅, x₃₇, x₃₉),
  v5 = f_a(x₄₁, x₄₃, x₄₅, x₄₇).

The truth tables of functions f_a, f_b and f_c are given below:

```
y₄ y₃ y₂ y₁ y₀ | f_a(y₀, y₁, y₂, y₃)  |  f_b(y₀, y₁, y₂, y₃)  |  f_c(y₀, y₁, y₂, y₃, y₄)
---------------+----------------------+-------------------------------------------------
0  0  0  0  0  |                   0  |                    0  |                        0
0  0  0  0  1  |                   0  |                    1  |                        1
0  0  0  1  0  |                   0  |                    1  |                        0
0  0  0  1  1  |                   1  |                    1  |                        1
0  0  1  0  0  |                   1  |                    0  |                        0
0  0  1  0  1  |                   0  |                    0  |                        0
0  0  1  1  0  |                   0  |                    0  |                        0
0  0  1  1  1  |                   1  |                    1  |                        0
0  1  0  0  0  |                   0  |                    0  |                        0
0  1  0  0  1  |                   1  |                    0  |                        0
0  1  0  1  0  |                   1  |                    1  |                        0
0  1  0  1  1  |                   1  |                    0  |                        1
0  1  1  0  0  |                   1  |                    1  |                        0
0  1  1  0  1  |                   0  |                    1  |                        1
0  1  1  1  0  |                   0  |                    0  |                        1
0  1  1  1  1  |                   1  |                    1  |                        1
1  0  0  0  0  |                                                                       1
1  0  0  0  1  |                                                                       1
1  0  0  1  0  |                                                                       1
1  0  0  1  1  |                                                                       0
1  0  1  0  0  |                                                                       1
1  0  1  0  1  |                                                                       0
1  0  1  1  0  |                                                                       1
1  0  1  1  1  |                                                                       0
1  1  0  0  0  |                                                                       0
1  1  0  0  1  |                                                                       0
1  1  0  1  0  |                                                                       1
1  1  0  1  1  |                                                                       1
1  1  1  0  0  |                                                                       0
1  1  1  0  1  |                                                                       1
1  1  1  1  0  |                                                                       1
1  1  1  1  1  |                                                                       1
```

Note: The tables have an equal number of 0 and 1 entries.

Reading the individual bits of the truth table, we can represent the functions with the
  following hex values:

- f_a: 0x9E98 = 0b1001111010011000
- f_b: 0xB48E = 0b1011010010001110
- f_c: 0xEC57E80A = 0b11101100010101111110000000001010


# Pseudo Random Number Generator
The PRNG of the Crypto1 library is used to generate nonces.

The Mifare PRNG is a 32-bit value. It is updated at each clock cycle by feeding in
  a new bit at the right (or by setting its seed entirely from the outside). The
  new bit is generated as a function of the least significant 16 bits using again
  a LFSR.

In the literature, shifting in a new bit is called the "suc" function.
  Depending on the literature, the `suc` function does 32 or just one iterations. It
  is generally clear from the context which notation is used.

Multiple iterations are written with a superposed integer:
- suc⁶⁴ (or suc²) corresponds to 64 iterations, and
- suc⁹⁶ (or suc³) to 96 iterations.

Since new bits only depend on the least significant 16 bits, the full 32-bit
  value only has a period of 2^16, and the most significant 16 bits can
  be used to recompute the least significant 16 bits. This is a major
  weakness of the Mifare PRNG, which is actively exploited.

The LFSR of the PRNG is defined by the polynomial x¹⁶ + x¹⁴ + x¹³ + x¹¹ + 1.
At any time k, the state sₖ of the LFSR is given by the 16-bit value
  sₖ=xₖxₖ₊₁…xₖ₊₁₅. At time k+1, the LFSR's state is updated to
  sₖ₊₁=xₖ₊₁xₖ₊₂…xₖ₊₁₆ by shifting the bits by one and adding xₖ₊₁₆ = xₖ⊕xₖ₊₂⊕xₖ₊₃⊕xₖ₊₅.

The LFSR of the PRNG can be implemented the same way as the one of the cipher, with
  taps on x₀, x₂, x₃ and x₅. As such, a PRNG state transition
  can be done by a bit-and of 0b10110100_00000000 = 0xB400 with the current state,
  followed by shifting in the parity of the result.

The LFSR state is initialized with a 32-bit seed. In early versions of Mifare cards,
  the seed was only dependent on the time since when the tag was powered on.

Given a period of just 65535, and since shifts happen every 9.44µs, it cycles every
  618ms.

# Mifare authentication
The following protocol is used to authenticate a Mifare Classic card:

During selection, the tag already shared its UID 'u' with the reader. Both
  sides are in possesion of this 4-byte value.

The goal of the authentication is to establish a shared encrypted communication
  using the sector key 'k'.

Both sides initialize the LFSB state (x₀x₁…x₄₇) with the key 'k'.

The reader initiates the authentication by sending an authentication request (`0x60`
  or `0x61`) for a specific sector.

The tag responds with a random 4-byte value, the challenge n_T. The challenge is
  normally generated by the PRNG. Fundamentally, there isn't any requirement for
  that, though.

Both sides XOR the challenge n_T with the UID 'u', and shift the result into their
  respective LFSR. That is, the LFSR is updated 32 times, with the shifted-in bit
  being xored  with the result of the combined n_T and u.
The output of the filter function f is ignored during this step.

The reader then constructs a 4-byte challeng n_R by . It sends this challenge to the
  tag, using the stream cipher to encrypt it. At the same time, the reader also
  feeds the unencrypted n_R into its own LFSR (similar to how n_T⊕u was fed
  into the LFSR). That is, after encoding each bit of n_R, the reader xors the
  unencrypted bit with the result of the LSFR feedback and uses it to shift the
  LFSR state.
In the same communication, the reader also sends the response to the challenge n_T,
  which is the suc⁶⁴(n_T) (that is, the PRNG value after 64 iterations, where the
  seed was n_T). The challenge response is sent encrypted using the normal
  stream cipher.

The tag decrypts the challenge n_R, and feeds the unencrypted bits into the LFSR as
  soon as they are available. It also verifies that the challeng response is correct.
It finishes the authentication by sending suc⁹⁶(n_T) (that is, the PRNG value
  after 96 iterations) to the reader.

At this stage the cipher has been initialized and both sides share the same LFSR state.
All further messages are encrypted using the output of the filter bits.

The tag finishes the authentication by sending the n_R back to the reader.
*/

class Crypto1:
  static TAPS ::= 0x846B_50D4_1170
  static MASK ::= 0xffff_ffff_ffff

  /**
  The LFSR state.
  Only the 48 least significant bits are used. The remaining bits can be ignored.
  */
  lfsr_state_/int := ?

  constructor .lfsr_state_:

  constructor --key/ByteArray:
    lfsr_state_ = 0x0
    key.do: | byte |
      8.repeat:
        lfsr_state_ <<= 1
        lfsr_state_ += byte & 1
        byte >>= 1

  /**
  Shifts a new bit into the LFSR.
  */
  shift:
    new_bit := (lfsr_state_ & TAPS).parity
    lfsr_state_ = ((lfsr_state_ << 1) | new_bit) & MASK

  /**
  Shifts a new bit into the LFSR, xoring it first with the $input bit.
  */
  shift input/int:
    new_bit := (lfsr_state_ & TAPS).parity ^ input
    lfsr_state_ = ((lfsr_state_ << 1) | new_bit) & MASK

  /**
  Returns the current cipher bit.

  This function is commonly referred to as "filter" function.
  */
  cipher_bit --should_shift/bool=true:
    v1 := f_b (bit_ 9) (bit_ 11) (bit_ 13) (bit_ 15)
    v2 := f_a (bit_ 17) (bit_ 19) (bit_ 21) (bit_ 23)
    v3 := f_a (bit_ 25) (bit_ 27) (bit_ 29) (bit_ 31)
    v4 := f_b (bit_ 33) (bit_ 35) (bit_ 37) (bit_ 39)
    v5 := f_a (bit_ 41) (bit_ 43) (bit_ 45) (bit_ 47)
    result := f_c v1 v2 v3 v4 v5
    if should_shift: shift
    return result

  bit_ n/int:
    return (lfsr_state_ >> (47 - n)) & 1

  f_a y0/int y1/int y2/int y3/int:
    bit_index := (y3 << 3) + (y2 << 2) + (y1 << 1) + y0
    return (0x9E98 >> bit_index) & 1

  f_b y3/int y2/int y1/int y0/int:
    bit_index := (y0 << 3) + (y1 << 2) + (y2 << 1) + y3
    return (0xB48E >> bit_index) & 1

  f_c y4/int y3/int y2/int y1/int y0/int:
    bit_index := (y0 << 4) + (y1 << 3) + (y2 << 2) + (y3 << 1) + y4
    return (0xEC57E80A >> bit_index) & 1

/**
A Crypto1 pseudo random number generator.

This implementation does not take time into account. Unless there are
  calls to $shift, the state stays unchanged.
*/
class Crypto1Prng:
  static TAPS ::= 0xB400
  static MASK ::= 0xFFFF_FFFF

  lfsr_state_/int := 0

  constructor seed/int=0:
    set_state seed

  constructor --seed_bytes/ByteArray:
    set_state --bytes=seed_bytes

  set_state state/int:
    lfsr_state_ = invert_ state

  set_state --bytes/ByteArray:
    set_state (LITTLE_ENDIAN.uint32 bytes 0)

  /**
  Returns the current state.

  Before returning shifts 32 times (but returns the old value).
  */
  current -> int:
    result := invert_ lfsr_state_
    return result

  /**
  Returns the current state as a 4-byte array.
  */
  current_bytes -> ByteArray:
    result := ByteArray 4
    LITTLE_ENDIAN.put_uint32 result 0 current
    return result

  /**
  Shifts the LFSR $n times.

  A shift introduces a single bit.
  */
  shift n/int=1:
    n.repeat:
      new_bit := (lfsr_state_ & TAPS).parity
      lfsr_state_ = ((lfsr_state_ << 1) | new_bit) & MASK

  invert_ x:
    result := 0
    32.repeat:
      result <<= 1
      result += x & 1
      x >>= 1
    return result

class MifareCryptoBase_:
  crypto1_/Crypto1

  constructor key/ByteArray:
    crypto1_ = Crypto1 --key=key

  crypt plain/ByteArray -> ByteArray:
    return ByteArray plain.size: |index|
      byte := plain[index]
      8.repeat: | bit_index |
        cipher_bit := crypto1_.cipher_bit
        byte ^= cipher_bit << bit_index
      byte

  /**
  Adds encrypted parity bits to the $cipher.

  Uses the given $plain text to extract the bits that should be used to crypt.
  The $current_crypto_bit is the current bit of the LFSR, which is used to
    encrypt the parity bit of the last byte.
  */
  add_parity -> ByteArray
      --plain/ByteArray
      --cipher/ByteArray
      --current_crypto_bit/int=(crypto1_.cipher_bit --should_shift=false):
    total_bits := plain.size * 9  // One parity bit per byte.
    total_bytes := (total_bits + 7) / 8

    result := ByteArray total_bytes

    target_index := total_bytes - 1
    target_bit_index := (total_bits - 1) % 8
    last_cipher_bit := current_crypto_bit

    for i := plain.size - 1; i >= 0; i--:
      byte_plain := plain[i]
      byte_cipher := cipher[i]

      parity_plain := byte_plain.parity ^ 1  // We want odd parity.
      // The parity bit is encrypted with the same bit as the next bit (which we stored
      // in $last_cipher_bit).
      parity_cipher := parity_plain ^ last_cipher_bit
      last_cipher_bit = (byte_plain ^ byte_cipher) & 0x01

      // Put the encrypted parity bit into the correct place in the cipher array.
      result[target_index] |= parity_cipher << target_bit_index
      target_bit_index--
      if target_bit_index < 0:
        target_index--
        target_bit_index = 7

      // Store the cipher byte right next to it.
      result[target_index] |= byte_cipher >> (7 - target_bit_index)
      target_index--
      if target_bit_index != 7:
        result[target_index] |= byte_cipher << (target_bit_index + 1)
    return result

  /**
  Given a byte array $bytes with parity bits, fixes them according to the
    the MiFare encryption.

  The parity bits are taken from the $plain text. They are then encrypted with
    the same cipher-bit that was used to encrypt the next bit of the $plain text.
  For the last byte, the cipher-bit is taken from the $current_crypto_bit.
  */
  fix_up_parity_bits bytes/ByteArray -> none
      --plain/ByteArray
      --cipher/ByteArray
      --current_crypto_bit/int=(crypto1_.cipher_bit --should_shift=false):
    if bytes.size == 0: return

    // The first byte of the $cipher and $bytes are the same.
    // In fact, we don't actually need the $cipher array, as we could
    // just extract it from the $bytes array.
    assert: bytes[0] == cipher[0]

    total_bits := plain.size * 9  // One parity bit per byte.
    total_bytes := (total_bits + 7) / 8
    assert: bytes.size == total_bytes

    target_index := total_bytes - 1
    target_bit_index := (total_bits - 1) % 8
    last_cipher_bit := current_crypto_bit

    for i := plain.size - 1; i >= 0; i--:
      byte_plain := plain[i]
      byte_cipher := cipher[i]

      parity_plain := byte_plain.parity ^ 1  // We want odd parity.
      parity_cipher := byte_cipher.parity ^ 1  // We want odd parity.
      // The parity bit is encrypted with the same bit as the next bit (which we stored
      // in $last_cipher_bit).
      // This is the parity bit that must be stored in the $bytes array.
      parity_result := parity_plain ^ last_cipher_bit

      last_cipher_bit = (byte_plain ^ byte_cipher) & 0x01

      // Fix the encrypted parity bit in the correct place in the cipher array.
      // The parity bit is currently $parity_cipher, but it should be $parity_result.

      bytes[target_index] ^= (parity_result ^ parity_cipher) << target_bit_index
      target_bit_index--
      if target_bit_index < 0:
        target_index--
        target_bit_index = 7

      // Decrement for the cipher byte that is right next to it.
      target_index--

class MifareCryptoReader extends MifareCryptoBase_:
  /**
  The key has been used to initialize the LFSR.
  */
  static STATE_0_KEY_INITIALIZED_ ::= 0
  /**
  The UID and tag nonce have been fed into the LFSR.
  */
  static STATE_1_UID_AND_NONCE_FED_ ::= 1
  /**
  The reader nonce has been encrypted and fed into the LFSR.
  */
  static STATE2_READER_NONCE_ENCRYPTED_AND_FED_ ::= 2
  /**
  The tag response has been checked.
  */
  static STATE_3_TAG_RESPONSE_CHECKED_ ::= 3

  state_/int := ?
  uid/ByteArray
  nonce_tag_/ByteArray? := null
  /**
  The expected challenge response of the tag.

  To finish the authentication the tag sends this response back to the reader.
  This response is suc⁹⁶(n_T), where n_T is the tag nonce.
  */
  expected_response_tag_/ByteArray? := null

  constructor --.uid/ByteArray key/ByteArray:
    state_ = STATE_0_KEY_INITIALIZED_
    super key

  /**
  Generates the challenge response to the tag's nonce.

  Does not encrypt the response.

  As a side-effect feeds the $uid xor $nonce_tag into the LFSR.
  */
  /**
  As a side-effect:
  - first feeds the $uid xor $nonce_tag into the LFSR.
  - then encrypts the $nonce_reader. At the same time, feeds the $nonce_reader
    into the LFSR.

  The $nonce_tag is also used to generate the challenge response; both for
    the reader, and the tag. See $compare_tag_response.
  */
  generate_challenge_response --nonce_tag/ByteArray --nonce_reader/ByteArray -> ByteArray:
    if state_ != STATE_0_KEY_INITIALIZED_: throw "Invalid state"

    // Feed the UID⊕nonce_tag into the LFSR.
    feed_uid_xor_nonce_tag_ --nonce_tag=nonce_tag

    if state_ != STATE_1_UID_AND_NONCE_FED_: throw "INVALID_STATE"
    if nonce_reader.size != 4: throw "INVALID_NONCE_READER"

    // Generate the challenge responses.
    prng := Crypto1Prng
    prng.set_state --bytes=nonce_tag

    prng.shift 64
    answer_reader := prng.current_bytes
    prng.shift 32
    expected_response_tag_ = prng.current_bytes

    return nonce_reader + answer_reader

  /**
  Encrypts the challenge response.

  As a side-effect feeds the nonce_reader (first 4 bytes of the challenge
    response) into the LFSR.
  */
  encrypt_challenge_response challenge_response -> ByteArray:
    if state_ != STATE_1_UID_AND_NONCE_FED_: throw "Invalid state"

    // Encrypt the nonce_reader, while feeding it into the LFSR.
    nonce_reader_cipher := ByteArray 4: |index|
      byte := challenge_response[index]
      8.repeat: | bit_index |
        cipher_bit := crypto1_.cipher_bit --should_shift=false
        plain_bit := (byte >> bit_index) & 1
        byte ^= cipher_bit << bit_index
        crypto1_.shift plain_bit
      byte

    state_ = STATE2_READER_NONCE_ENCRYPTED_AND_FED_

    answer_reader := challenge_response[4..]
    answer_reader_cipher := crypt answer_reader --no-check_state

    return nonce_reader_cipher + answer_reader_cipher

  /**
  Compares the given tag response to the expected one.

  Returns true if the tag response is correct; false otherwise.

  This is the last step of the authentication process. The tag is supposed
    to send an encrypted successor of the tag nonce. This method checks
    that the response is correct.

  This method changes the internal state so that the $crypt method is available.
  */
  compare_tag_response tag_response/ByteArray -> bool:
    if state_ != STATE2_READER_NONCE_ENCRYPTED_AND_FED_: throw "Invalid state"
    if tag_response.size != 4: throw "Invalid tag response"
    assert: expected_response_tag_ != null

    tag_response = crypt tag_response --no-check_state

    result := tag_response == expected_response_tag_
    state_ = STATE_3_TAG_RESPONSE_CHECKED_
    return result

  crypt plain/ByteArray --check_state/bool=true -> ByteArray:
    if check_state and state_ != STATE_3_TAG_RESPONSE_CHECKED_: throw "Invalid state"

    return super plain

  /**
  Feeds the $uid and $nonce_tag into the LFSR.

  This is the second step of the authentication (after the initial key setting).

  The $nonce_tag is sent by the tag as a response to an authentication request.
    It is generally generated by a $Crypto1Prng, but non-compliant tags can use
    any value.

  The $nonce_tag is stored internally, so it is available for the
  */
  feed_uid_xor_nonce_tag_ --nonce_tag/ByteArray:
    if state_ != STATE_0_KEY_INITIALIZED_: throw "INVALID_STATE"
    if uid.size != 4: throw "INVALID_UID"
    if nonce_tag.size != 4: throw "INVALID_NONCE_TAG"

    xored := ByteArray 4: uid[it] ^ nonce_tag[it]

    xored_value := LITTLE_ENDIAN.uint32 xored 0
    32.repeat:
      crypto1_.shift xored_value & 1
      xored_value >>= 1

    state_ = STATE_1_UID_AND_NONCE_FED_

class MifareCryptoWriter extends MifareCryptoBase_:
  /**
  The key has been used to initialize the LFSR.
  */
  static STATE_0_KEY_INITIALIZED_ ::= 0
  /**
  The UID and tag nonce have been fed into the LFSR.
  */
  static STATE_1_UID_AND_NONCE_FED_ ::= 1
  /**
  The reader nonce has been encrypted and fed into the LFSR.
  */
  static STATE2_READER_NONCE_ENCRYPTED_AND_FED_ ::= 2
  /**
  The reader response has been checked.
  */
  static STATE_3_READER_RESPONSE_CHECKED_ ::= 3

  state_/int := ?
  uid/ByteArray
  nonce_tag_/ByteArray? := null

  constructor --.uid/ByteArray key/ByteArray:
    state_ = STATE_0_KEY_INITIALIZED_
    super key

  /**
  Generates a nonce for the tag.

  Tags that are compliant get their nonce from a $Crypto1Prng. Non-compliant
    tags can use any value.

  Initializes a $Crypto1Prng with the given $seed and forwards the generater
    16 times to reach a consistent state.

  Returns the result of the PRNG after the 16 iterations.
  */
  generate_nonce --seed/int -> ByteArray:
    prng := Crypto1Prng seed
    prng.shift 16
    return prng.current_bytes

  /**
  Starts the authentication process.

  The reader starts by sending an authentication request. The tag
    starts the authentication process by sending back a nonce.

  As part of the authentication process feeds the $uid xor $tag_nonce into
    the LFSR.

  The $tag_nonce is generally generated by a $Crypto1Prng (see $generate_nonce),
    but non-compliant tags can use any value.

  The $tag_nonce is later used to generate the challenge response; both for
    the reader, and the tag. See $handle_reader_response.
  */
  start_authentication --tag_nonce/ByteArray:
    if state_ != STATE_0_KEY_INITIALIZED_: throw "INVALID_STATE"
    if uid.size != 4: throw "INVALID_UID"
    if tag_nonce.size != 4: throw "INVALID_NONCE_TAG"

    nonce_tag_ = tag_nonce

    xored := ByteArray 4: uid[it] ^ tag_nonce[it]

    xored_value := LITTLE_ENDIAN.uint32 xored 0
    32.repeat:
      crypto1_.shift xored_value & 1
      xored_value >>= 1

    state_ = STATE_1_UID_AND_NONCE_FED_

  /**
  Handles the reader's response.

  This is the second step of the authentication process. After it has received
    the tag's nonce, the reader sends its own nonce, together with the challenge
    response to the tag.

  Returns the tag's challenge response, finishing the authentication.
  */
  handle_reader_response -> ByteArray
      --in_place/bool
      reader_response/ByteArray
      --check_challenge_response/bool=true:
    if state_ != STATE_1_UID_AND_NONCE_FED_: throw "INVALID_STATE"
    if reader_response.size != 8: throw "INVALID_READER_RESPONSE"

    encrypted_nonce_reader := reader_response[0..4]
    challenge_response := reader_response[4..8]

    // Decrypt the reader nonce, while feeding it into the LFSR.
    // We don't care for the result, as the decrypted nonce is
    // immediately fed into the LFSR.
    4.repeat: |index|
      byte := encrypted_nonce_reader[index]
      8.repeat: | bit_index |
        cipher_bit := crypto1_.cipher_bit --should_shift=false
        byte ^= cipher_bit << bit_index
        plain_bit := (byte >> bit_index) & 1
        crypto1_.shift plain_bit
      byte

    state_ = STATE2_READER_NONCE_ENCRYPTED_AND_FED_

    prng := Crypto1Prng --seed_bytes=nonce_tag_
    prng.shift 64
    expected_challenge_response_reader := prng.current_bytes
    prng.shift 32
    response_tag := prng.current_bytes

    // Decrypt the challenge response.
    crypt --in_place challenge_response --no-check_state

    if check_challenge_response:
      if challenge_response != expected_challenge_response_reader:
        throw "INVALID_CHALLENGE_RESPONSE"
    state_ = STATE_3_READER_RESPONSE_CHECKED_

    crypt --in_place response_tag
    return response_tag

  crypt --in_place/bool data/ByteArray --check_state/bool=true --add_parity_bits/bool=false -> ByteArray:
    if in_place and add_parity_bits: throw "in_place and add_parity_bits are mutually exclusive"
    if check_state and state_ != STATE_3_READER_RESPONSE_CHECKED_: throw "Invalid state"

    result /ByteArray := ?
    if add_parity_bits:
      result = ByteArray (data.size + 7) / 8
    else if not in_place:
      result = data.copy
    else:
      result = data

    result_index := 0
    result_bit_index := 0
    data.size.repeat: |index|
      plain_byte := data[index]
      cipher_byte := plain_byte
      8.repeat: | bit_index |
        cipher_bit := crypto1_.cipher_bit
        cipher_byte ^= cipher_bit << bit_index
      result[result_index++] = cipher_byte << result_bit_index
      if add_parity_bits:
        if result_bit_index != 0:
          result[result_index] |= cipher_byte >> (8 - result_bit_index)
        plain_parity := plain_byte.parity ^ 1  // We want the odd parity.
        cipher_parity := plain_parity ^ (crypto1_.cipher_bit --should_shift=false)
        result[result_index] |= cipher_parity << result_bit_index
        result_bit_index = (result_bit_index + 1) % 8

    return result

main:
  // Given the diagram at https://en.wikipedia.org/wiki/Crypto-1#/media/File:Crypto1.png
  // Then key[0] & 0 is equal to key_0 and key[6] & 0x80 is equal to key_47.
  key := #[ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]

  uid := #[0xcd, 0x76, 0x92, 0x74]
  n_t := #[0x0e, 0x61, 0x64, 0xD6]
  n_r := #[0x15, 0x45, 0x90, 0xa8]

  crypto_reader := MifareCryptoReader key --uid=uid
  crypto_writer := MifareCryptoWriter key --uid=uid

  print "tag_nonce: $n_t"

  crypto_writer.start_authentication --tag_nonce=n_t
  reader_response := crypto_reader.generate_challenge_response --nonce_tag=n_t --nonce_reader=n_r
  encrypted_reader_response := crypto_reader.encrypt_challenge_response reader_response
  reader_response_with_parity := crypto_reader.add_parity
      --plain=reader_response
      --cipher=encrypted_reader_response

  print "reader response: $reader_response"
  print "encrypted reader response: $encrypted_reader_response"
  print "encrypted reader response with parity: $reader_response_with_parity"

  writer_response := crypto_writer.handle_reader_response --in_place encrypted_reader_response

  print "writer_response: $writer_response"

  succeeded := crypto_reader.compare_tag_response writer_response
  print "Authentication succeeded: $succeeded"

  // Both states are now the same:
  print "Reader state: $(%x crypto_reader.crypto1_.lfsr_state_)"
  print "Tag state:    $(%x crypto_writer.crypto1_.lfsr_state_)"
