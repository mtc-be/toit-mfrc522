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

If the tag was already authenticated, a nested authentication takes place. In this
  case the tag encrypts the tag n_T while sending it. It starts by
  combining UID⊕nonce_tag (32 bits), then encrypts each bit of n_T, before it
  shifts in the next bit of the xored value.
if the tag was not authenticated, it sends the challenge n_T unencrypted. It still
  shifts in the xored value. The output of the filter function f is ignored in this
  case.
In total, the LFSR is updated 32 times, with the shifted-in bit being xored with the
  result of the combined n_T and u.

The reader uses the n_T to get to the same state as the tag. If the authentication
  is not nested, it just shifts in the xored value (similarly to how the tag did it).
If the authentication is nested, it first decrypts each bit of the challenge n_T,
  then shifts in the next bit of the xored value.

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
  soon as they are available. It also verifies that the challenge response is correct.
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
  lfsr_state_/int := 0

  constructor .lfsr_state_=0:

  constructor --key/ByteArray:
    set_key key

  /**
  The current LFSR state.

  The bit order is such that new bits are shifted in from the right.
    That is, a shifted bit takes the position of the least significant bit.

  The Crypto-1 LFSR has 48 bits.
  */
  state -> int:
    return lfsr_state_

  /**
  Returns the current LFSR state as a byte array.

  The least-significant bit of the least-significant (first) byte
    is the most-significant bit of the state.
  The most-significant bit of the most-significant (last) byte
    is the least-significant bit of the state.
  */
  state --as_bytes -> ByteArray:
    current_state := lfsr_state_
    inverted := 0
    48.repeat:
      inverted <<= 1
      inverted += current_state & 1
      current_state >>= 1
    result := ByteArray 6
    LITTLE_ENDIAN.put_uint32 result 0 (inverted & 0xffffffff)
    LITTLE_ENDIAN.put_uint16 result 4 (inverted >> 32)
    return result

  /**
  Sets the LFSR state to the given $key.
  */
  set_key key/ByteArray:
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
  Shifts $bit_count new bits into the LFSR, xoring them with the
    $input_bits (least significant bits first) first.
  */
  shift input_bits/int --bit_count/int:
    bit_count.repeat:
      shift input_bits & 1
      input_bits >>= 1

  /**
  Returns the current cipher bit.

  This function is commonly referred to as "filter" function.
  */
  cipher_bit --should_shift/bool=true:
    v1 := f_b_ (bit_ 9) (bit_ 11) (bit_ 13) (bit_ 15)
    v2 := f_a_ (bit_ 17) (bit_ 19) (bit_ 21) (bit_ 23)
    v3 := f_a_ (bit_ 25) (bit_ 27) (bit_ 29) (bit_ 31)
    v4 := f_b_ (bit_ 33) (bit_ 35) (bit_ 37) (bit_ 39)
    v5 := f_a_ (bit_ 41) (bit_ 43) (bit_ 45) (bit_ 47)
    result := f_c_ v1 v2 v3 v4 v5
    if should_shift: shift
    return result

  /**
  En/decrypts the given plain/cipher $text using the current state.

  Crypts the $text by xoring each bit with the cipher bit, starting
    with the least significant bit of the first byte.
  */
  crypt text/ByteArray -> ByteArray:
    return ByteArray text.size: |index|
      byte := text[index]
      8.repeat: | bit_index |
        cipher_bit := cipher_bit
        byte ^= cipher_bit << bit_index
      byte

  /**
  En/decrypts the given plain/cipher $text while feeding in the
    $feed_crypted value that is xored with the same cipher bit as the
    $text.

  Each text-bit is xored with the cipher bit first, and then a bit
    (lowest significant bits first) of the $feed_crypted is xored with
    with the same cipher bit and shifted into the LFSR.

  The $text is not used to shift the LFSR.
  */
  crypt text/ByteArray --feed_crypted/int -> ByteArray:
    return ByteArray text.size: |index|
      byte := text[index]
      8.repeat: | bit_index |
        cipher_bit := cipher_bit --should_shift=false
        byte ^= cipher_bit << bit_index
        shift ((feed_crypted & 1) ^ cipher_bit)
        feed_crypted >>= 1
      byte

  /**
  En/decrypts the given plain/cipher $text while feeding in the
    $feed_plain value.

  Each text-bit is xored with the cipher bit first, and then a bit
    (lowest significant bits first) of the $feed_plain is shifted
    into the LFSR.

  The $text is not used to shift the LFSR.
  */
  crypt text/ByteArray --feed_plain/int -> ByteArray:
    return ByteArray text.size: |index|
      byte := text[index]
      8.repeat: | bit_index |
        cipher_bit := cipher_bit --should_shift=false
        byte ^= cipher_bit << bit_index
        shift (feed_plain & 1)
        feed_plain >>= 1
      byte

  bit_ n/int:
    return (lfsr_state_ >> (47 - n)) & 1

  f_a_ y0/int y1/int y2/int y3/int:
    bit_index := (y3 << 3) + (y2 << 2) + (y1 << 1) + y0
    return (0x9E98 >> bit_index) & 1

  f_b_ y3/int y2/int y1/int y0/int:
    bit_index := (y0 << 3) + (y1 << 2) + (y2 << 1) + y3
    return (0xB48E >> bit_index) & 1

  f_c_ y4/int y3/int y2/int y1/int y0/int:
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

  /**
  The current state of the LFSR.

  The bit order is such that new bits are shifted in from the right.
    That is, a shifted bit takes the position of the least significant bit.

  The LFSR has 32 bits.
  */
  state -> int:
    return lfsr_state_

  /**
  Returns the current state as a 4-byte array.

  The least-significant bit of the least-significant (first) byte
    is the most-significant bit of the state.
  The most-significant bit of the most-significant (last) byte
    is the least-significant bit of the state.
  */
  state --as_bytes/bool -> ByteArray:
    if not as_bytes: throw "INVALID_ARGUMENT"
    result := ByteArray 4
    LITTLE_ENDIAN.put_uint32 result 0 (invert_ lfsr_state_)
    return result

  /**
  Sets the current state of the LFSR.
  */
  set_state state/int:
    lfsr_state_ = state

  /**
  Sets the current state of the LFSR given a 4-byte array.

  The least-significant bit of the least-significant (first) byte
    becomes the most-significant bit of the state.
  */
  set_state --bytes/ByteArray:
    set_state (invert_ (LITTLE_ENDIAN.uint32 bytes 0))

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
  crypto1_/Crypto1 := Crypto1

  /**
  Sets the internal state of the crypto1 LFSR to the given $key.
  */
  set_key_ key/ByteArray:
    if key.size != 6: throw "Invalid key size"
    crypto1_.set_key key

  /**
  En/decrypts the given plain/cipher $text using the current state of the $crypto1_.
  */
  crypt_ text/ByteArray -> ByteArray:
    return crypto1_.crypt text

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
  The reader was constructed, but no authentication has been started yet.
  */
  static STATE_CONSTRUCTED_ ::= 0
  /**
  The authentication has started, but no request has been sent yet.
    At this stage we have the new key, but haven't used it yet.
  */
  static STATE_AUTHENTICATION_STARTED_ ::= 1
  /**
  See $STATE_AUTHENTICATION_STARTED_, but for nested authentication.
  */
  static STATE_NESTED_AUTHENTICATION_STARTED_ ::= 2
  /**
  The reader has sent an authentication, and is waiting for the
    unencrypted nonce.
  */
  static STATE_WAITING_FOR_NONCE_TAG_ ::= 3
  /**
  The reader has sent a nested authentication, and is waiting for the
    encrypted nonce.
  */
  static STATE_WAITING_FOR_NESTED_NONCE_TAG_ ::= 4
  /**
  The new crypto1 cipher was set to the new key.
  */
  static STATE_KEY_INITIALIZED_ ::= 5
  /**
  The UID and tag nonce have been fed into the LFSR.
  */
  static STATE_UID_AND_NONCE_FED_ ::= 6
  /**
  The reader nonce has been encrypted and fed into the LFSR.
  */
  static STATE_READER_NONCE_ENCRYPTED_AND_FED_ ::= 7
  /**
  The tag response has been checked, and the reader is now authenticated.
  */
  static STATE_TAG_RESPONSE_CHECKED_ ::= 8
  /** See $STATE_TAG_RESPONSE_CHECKED_. */
  static STATE_AUTHENTICATED_ ::= STATE_TAG_RESPONSE_CHECKED_

  state_/int := ?
  uid/ByteArray
  nonce_tag_/ByteArray? := null
  /**
  The expected challenge response of the tag.

  To finish the authentication the tag sends this response back to the reader.
  This response is suc⁹⁶(n_T), where n_T is the tag nonce.
  */
  expected_response_tag_/ByteArray? := null
  /**
  The new key when switching from state $STATE_AUTHENTICATION_STARTED_ (or
    $STATE_NESTED_AUTHENTICATION_STARTED_) to $STATE_WAITING_FOR_NONCE_TAG_ (
    or $STATE_WAITING_FOR_NESTED_NONCE_TAG_).
  */
  new_key_/ByteArray? := null

  /**
  Constructs a new crypto reader.

  The $uid must be the UID of the tag, or, for 7-byte UIDs, the last 4 bytes.
  */
  constructor --.uid/ByteArray:
    if uid.size != 4: throw "INVALID_UID"
    state_ = STATE_CONSTRUCTED_

  start_authentication --key/ByteArray:
    if state_ != STATE_CONSTRUCTED_ and state_ != STATE_AUTHENTICATED_:
      throw "Invalid state"
    new_key_ = key
    if state_ == STATE_CONSTRUCTED_:
      // First authentication.
      state_ = STATE_AUTHENTICATION_STARTED_
    else:
      // Nested authentication.
      state_ = STATE_NESTED_AUTHENTICATION_STARTED_

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
    if state_ != STATE_UID_AND_NONCE_FED_: throw "INVALID_STATE"
    if nonce_reader.size != 4: throw "INVALID_NONCE_READER"

    // Generate the challenge responses.
    prng := Crypto1Prng
    prng.set_state --bytes=nonce_tag

    prng.shift 64
    answer_reader := prng.state --as_bytes
    prng.shift 32
    expected_response_tag_ = prng.state --as_bytes

    return nonce_reader + answer_reader

  /**
  Compares the given tag response to the expected one.

  Returns true if the tag response is correct; false otherwise.

  This is the last step of the authentication process. The tag is supposed
    to send an encrypted successor of the tag nonce. This method checks
    that the response is correct.

  This method changes the internal state to authenticated. From now
    on all messages can be en/decrypted.
  */
  compare_tag_response tag_response/ByteArray -> bool:
    if state_ != STATE_READER_NONCE_ENCRYPTED_AND_FED_: throw "Invalid state"
    if tag_response.size != 4: throw "Invalid tag response"
    assert: expected_response_tag_ != null

    result := tag_response == expected_response_tag_
    state_ = STATE_TAG_RESPONSE_CHECKED_
    return result

  /**
  Decrypts the given ciphertext that was received from the writer.

  Depending on the internal state, the ciphertext might be decrypted
    differently, and or have a different impact on the crypto1 LFSR.
  */
  decrypt ciphertext/ByteArray -> ByteArray:
    if state_ == STATE_WAITING_FOR_NONCE_TAG_ or
        state_ == STATE_WAITING_FOR_NESTED_NONCE_TAG_:
      is_nested := state_ == STATE_WAITING_FOR_NESTED_NONCE_TAG_
      set_key_ new_key_
      new_key_ = null
      state_ = STATE_KEY_INITIALIZED_
      return decrypt_nonce_tag_
          --nonce_tag=ciphertext
          --nested=is_nested

    if state_ == STATE_READER_NONCE_ENCRYPTED_AND_FED_:
      return crypt_ ciphertext

    if state_ == STATE_AUTHENTICATED_:
      return crypt_ ciphertext

    throw "Invalid state"

  encrypt plaintext/ByteArray -> ByteArray:
    if state_ == STATE_AUTHENTICATION_STARTED_:
      // Send out the request without any encryption.
      state_ = STATE_WAITING_FOR_NONCE_TAG_
      return plaintext

    if state_ == STATE_NESTED_AUTHENTICATION_STARTED_:
      // Use the existing crypto1 to encrypt the request.
      encrypted := crypt_ plaintext
      state_ = STATE_WAITING_FOR_NESTED_NONCE_TAG_
      return encrypted

    if state_ == STATE_UID_AND_NONCE_FED_:
      // The challenge response was created, and is now sent to the tag.
      return encrypt_challenge_response_ plaintext

    if state_ == STATE_TAG_RESPONSE_CHECKED_:
      // The tag response was checked, and the reader is now sending
      // the encrypted nonce.
      return crypt_ plaintext

    // TODO(florian): we need to be sure we don't
    // throw for stupid reasons.
    // Currently just return null.
    return plaintext
    throw "Invalid state $state_."

  /**
  Decrypts the tag's nonce.
  If this isn't a nested authentication returns the given $nonce_tag verbatim.

  While decrypting feeds the $uid and $nonce_tag into the LFSR.

  This is the second step of the authentication (after the initial key setting).

  The $nonce_tag is sent by the tag as a response to an authentication request.
    It is generally generated by a $Crypto1Prng, but non-compliant tags can use
    any value.

  if $nested is true, then the $nonce_tag has been encrypted with the current key.
    This is used for nested authentication.
  */
  decrypt_nonce_tag_ --nonce_tag/ByteArray --nested/bool -> ByteArray:
    if state_ != STATE_KEY_INITIALIZED_: throw "Invalid state"
    if uid.size != 4: throw "INVALID_UID"
    if nonce_tag.size != 4: throw "INVALID_NONCE_TAG"

    uid_value := LITTLE_ENDIAN.uint32 uid 0
    nonce_tag_value := LITTLE_ENDIAN.uint32 nonce_tag 0
    xored_value :=  uid_value ^ nonce_tag_value

    result/ByteArray := ?
    if nested:
      result = crypto1_.crypt nonce_tag --feed_crypted=xored_value
    else:
      // Simply feed the UID and nonce_tag into the LFSR.
      crypto1_.shift xored_value --bit_count=32
      result = nonce_tag

    state_ = STATE_UID_AND_NONCE_FED_
    return result

  /**
  Encrypts the challenge response.

  As a side-effect feeds the nonce_reader (first 4 bytes of the challenge
    response) into the LFSR.
  */
  encrypt_challenge_response_ challenge_response/ByteArray -> ByteArray:
    if state_ != STATE_UID_AND_NONCE_FED_: throw "Invalid state"
    if challenge_response.size != 8: throw "Invalid challenge response"

    nonce_reader := challenge_response[0..4]
    // Encrypt the nonce_reader, while feeding it into the LFSR.
    plain_bits := LITTLE_ENDIAN.uint32 nonce_reader 0
    nonce_reader_ciphertext := crypto1_.crypt nonce_reader --feed_plain=plain_bits

    state_ = STATE_READER_NONCE_ENCRYPTED_AND_FED_

    answer_reader := challenge_response[4..]
    answer_reader_ciphertext := crypt_ answer_reader

    return nonce_reader_ciphertext + answer_reader_ciphertext

class MifareCryptoWriter extends MifareCryptoBase_:
  /**
  The writer was constructor, but no authentication has been started yet.
  */
  static STATE_CONSTRUCTED_ ::= 0
  /**
  The authentication has started, but the nonce hasn't been sent yet.
    At this stage we have the key, but haven't used it yet.
  */
  static STATE_WAITING_FOR_NONCE_TAG_ ::= 1
  /**
  See $STATE_WAITING_FOR_NONCE_TAG_, but for nested authentication.
  */
  static STATE_WAITING_FOR_NESTED_NONCE_TAG_ ::= 2
  /**
  The tag nonce has been sent, and we are waiting for the challenge response.
  */
  static STATE_WAITING_FOR_CHALLENGE_RESPONSE_ ::= 3
  /**
  The reader response has been received and decrypted.
    We now need to generate the final message.
  */
  static STATE_WAITING_FOR_FINAL_MESSAGE_REQUEST_ ::= 4
  /**
  The final message has been computed, but not sent yet.
  */
  static STATE_ABOUT_TO_SEND_FINAL_MESSAGE_ ::= 5
  /**
  The final message has been sent, and the authentication is complete.
  */
  static STATE_AUTHENTICATED_ ::= 6

  state_/int := ?
  uid/ByteArray
  /**
  The nonce that the tag sends to the reader.
  It is obtained during encryption, and is used to verify the challenge
    response from the reader and to compute the final authentication message.
  */
  nonce_tag_/ByteArray? := null

  /**
  Constructs a new crypto writer.

  The $uid must be the UID of the tag, or, for 7-byte UIDs, the last 4 bytes.
  */
  constructor --.uid/ByteArray:
    if uid.size != 4: throw "INVALID_UID"
    state_ = STATE_CONSTRUCTED_

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
    return prng.state --as_bytes

  /**
  Starts the authentication process.

  The reader starts by sending an authentication request which triggers
    a call to this function. The tag is now supposed to send a nonce
    (possibly one generated by $generate_nonce) to the reader.
  */
  start_authentication --key/ByteArray:
    if state_ != STATE_CONSTRUCTED_ and state_ != STATE_AUTHENTICATED_:
      throw "INVALID_STATE"
    set_key_ key
    if state_ == STATE_CONSTRUCTED_:
      state_ = STATE_WAITING_FOR_NONCE_TAG_
    else:
      // Nested authentication.
      state_ = STATE_WAITING_FOR_NESTED_NONCE_TAG_

  /**
  Computes the final message of the authentication process.

  The $response must be the reader's response, consisting of the reader's nonce and
    the challenge response.

  If $check is true, verifies that the challenge response is correct.

  This is the second step of the authentication process. After it has received
    the tag's nonce, the reader sends its own nonce, together with the challenge
    response to the tag.

  Returns the tag's challenge response (the final message), which must be sent
    to finish the authentication.
  */
  compute_final_message response/ByteArray --check/bool=true -> ByteArray:
    if state_ != STATE_WAITING_FOR_FINAL_MESSAGE_REQUEST_:
      throw "INVALID_STATE"
    prng := Crypto1Prng --seed_bytes=nonce_tag_
    prng.shift 64
    expected_challenge_response_reader := prng.state --as_bytes

    if check:
      challenge_response := response[4..]
      if challenge_response != expected_challenge_response_reader:
        throw "INVALID_CHALLENGE_RESPONSE"

    prng.shift 32
    final_authentication_message := prng.state --as_bytes
    state_ = STATE_ABOUT_TO_SEND_FINAL_MESSAGE_
    return final_authentication_message

  encrypt plaintext/ByteArray -> ByteArray:
    if state_ == STATE_WAITING_FOR_NONCE_TAG_ or state_ == STATE_WAITING_FOR_NESTED_NONCE_TAG_:
      is_nested := state_ == STATE_WAITING_FOR_NESTED_NONCE_TAG_
      return encrypt_nonce_tag_ plaintext --nested=is_nested
    if state_ == STATE_ABOUT_TO_SEND_FINAL_MESSAGE_:
      state_ = STATE_AUTHENTICATED_
      // Fall through to encrypting the final message.
    return crypt_ plaintext

  decrypt ciphertext/ByteArray -> ByteArray:
    if state_ == STATE_WAITING_FOR_CHALLENGE_RESPONSE_:
      return decrypt_reader_response_ ciphertext
    else if state_ == STATE_CONSTRUCTED_:
      // Probably the request to start encryption.
      return ciphertext
    return crypt_ ciphertext

  /**
  Encrypts the tag nonce before sending it to the reader.

  For nested authentications, the $nonce_tag is already with the
    new key. For non-nested authentications, the $nonce_tag is
    sent in the clear.

  As part of the operation feeds the $uid xor $nonce_tag into the LFSR.

  The $nonce_tag is generally generated by a $Crypto1Prng (see $generate_nonce),
    but non-compliant tags can use any value.

  The $nonce_tag is later used to verify the challenge response and to
    compute the final message. See $decrypt_reader_response_ and
    $compute_final_message.

  Remembers the $nonce_tag, so it can be used to verify the challenge response
    later.
  */
  encrypt_nonce_tag_ nonce_tag/ByteArray --nested/bool -> ByteArray:
    if state_ != STATE_WAITING_FOR_NONCE_TAG_ and
        state_ != STATE_WAITING_FOR_NESTED_NONCE_TAG_:
      throw "INVALID_STATE"
    if nonce_tag.size != 4: throw "INVALID_NONCE_TAG"
    nonce_tag_ = nonce_tag

    xored := ByteArray 4: uid[it] ^ nonce_tag[it]
    xored_value := LITTLE_ENDIAN.uint32 xored 0

    result/ByteArray := ?
    if nested:
      result = crypto1_.crypt nonce_tag --feed_plain=xored_value
    else:
      crypto1_.shift xored_value --bit_count=32
      result = nonce_tag

    state_ = STATE_WAITING_FOR_CHALLENGE_RESPONSE_
    return result

  decrypt_reader_response_ response/ByteArray -> ByteArray:
    if state_ != STATE_WAITING_FOR_CHALLENGE_RESPONSE_: throw "INVALID_STATE"
    if response.size != 8: throw "INVALID_READER_RESPONSE"

    encrypted_nonce_reader := response[0..4]
    encrypted_challenge_response := response[4..8]

    // Decrypt the reader nonce, while feeding it into the LFSR.
    encryped_bits := LITTLE_ENDIAN.uint32 encrypted_nonce_reader 0
    nonce_reader := crypto1_.crypt encrypted_nonce_reader --feed_crypted=encryped_bits

    state_ = STATE_WAITING_FOR_FINAL_MESSAGE_REQUEST_

    // Decrypt the challenge response.
    challenge_response := crypt_ encrypted_challenge_response
    return nonce_reader + challenge_response


main:
  // Given the diagram at https://en.wikipedia.org/wiki/Crypto-1#/media/File:Crypto1.png
  // Then key[0] & 0 is equal to key_0 and key[6] & 0x80 is equal to key_47.
  key := #[ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]

  uid := #[0xcd, 0x76, 0x92, 0x74]
  n_t := #[0x0e, 0x61, 0x64, 0xD6]
  n_r := #[0x15, 0x45, 0x90, 0xa8]
  print "nonce_tag: $n_t"

  crypto_reader := MifareCryptoReader --uid=uid
  crypto_writer := MifareCryptoWriter --uid=uid

  2.repeat: | iteration/int |
    block := iteration
    // The write initiaties the authentication.
    // Note that the 'start_authentication' must happen before sending the
    // authentication command. This is, because the response might already
    // come back encrypted, in which case we need to know the key.
    crypto_reader.start_authentication --key=key
    encrypted_auth_request := crypto_reader.encrypt #[0x60, block]  // Authentication command.

    decrypted_auth_request := crypto_writer.decrypt encrypted_auth_request
    print "Decrypt auth request: $decrypted_auth_request"

    // The tag has received the authentication request.
    crypto_writer.start_authentication --key=key

    // The tag sends the tag nonce.
    encrypted_nonce_tag := crypto_writer.encrypt n_t
    // If we aren't nested, the encrypted_nonce_tag is equal to the tag nonce.

    // The reader receives the tag nonce and decrypts it.
    crypto_reader.decrypt encrypted_nonce_tag

    print "Reader state 0: $(%x crypto_reader.crypto1_.lfsr_state_)"
    print "Tag state 0:    $(%x crypto_writer.crypto1_.lfsr_state_)"

    // It generates a response, consisting of the reader nonce and
    // the challenge response.
    reader_response_plain := crypto_reader.generate_challenge_response --nonce_tag=n_t --nonce_reader=n_r
    encrypted_reader_response := crypto_reader.encrypt reader_response_plain

    reader_response_with_parity := crypto_reader.add_parity
        --plain=reader_response_plain
        --cipher=encrypted_reader_response

    print "reader response: $reader_response_plain"
    print "reader response cipher: $encrypted_reader_response"
    print "encrypted reader response with parity: $reader_response_with_parity"

    // The tag receives the response.
    decrypted_reader_response := crypto_writer.decrypt encrypted_reader_response

    print "Reader state 1: $(%x crypto_reader.crypto1_.lfsr_state_)"
    print "Tag state 1:    $(%x crypto_writer.crypto1_.lfsr_state_)"

    // It now checks that the response was correct and generates the final
    // message.
    final_message := crypto_writer.compute_final_message decrypted_reader_response
    // It sends it encrypted to the reader.
    encrypted_final_message := crypto_writer.encrypt final_message

    // The reader receives the message, decrypts it and compares it to the
    // expected value.
    decrypted_final_message := crypto_reader.decrypt encrypted_final_message

    print "Reader state 2: $(%x crypto_reader.crypto1_.lfsr_state_)"
    print "Tag state 2:    $(%x crypto_writer.crypto1_.lfsr_state_)"

    succeeded := crypto_reader.compare_tag_response decrypted_final_message
    print "Authentication succeeded: $succeeded"

    // At this point, the reader and the tag are in the same state.
    print "Reader state: $(%x crypto_reader.crypto1_.lfsr_state_)"
    print "Tag state:    $(%x crypto_writer.crypto1_.lfsr_state_)"
