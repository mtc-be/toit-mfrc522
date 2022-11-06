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
  which is the suc²(n_T) (that is, the PRNG value after 64 iterations, where the
  seed was n_T). The challenge response is sent encrypted using the normal
  stream cipher.

The tag decrypts the challenge n_R, and feeds the unencrypted bits into the LFSR as
  soon as they are available. It also verifies that the challeng response is correct.
It finishes the authentication by sending suc³(n_R) (that is, the PRNG value
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


interface ConnectionEncrypter:
  /**
  En/decrypts the given $bytes.

  If $in_place is true, modifies the given $bytes in place. Otherwise creates a copy.
  */
  crypt --in_place/bool bytes/ByteArray

class IdentityEncrypter implements ConnectionEncrypter:
  crypt --in_place/bool bytes/ByteArray:
    if not in_place: throw "INVALID_ARGUMENT"
    return bytes

class Crypto1Encrypter implements ConnectionEncrypter:
  crypto1/Crypto1

  constructor key/ByteArray:
    crypto1 = Crypto1 --key=key

  crypt --in_place/bool bytes/ByteArray -> ByteArray:
    if not in_place: bytes = bytes.copy
    bytes.size.repeat: | byte_index |
      byte := bytes[byte_index]
      8.repeat:
        byte ^= crypto1.cipher_bit << it
      bytes[byte_index] = byte
    return bytes

main:
//  key := #[ 0xd7, 0x96, 0x86, 0x65, 0xfb, 0x36 ]

  // Given the diagram at https://en.wikipedia.org/wiki/Crypto-1#/media/File:Crypto1.png
  // Then key[0] & 0 is equal to key_0 and key[6] & 0x80 is equal to key_47.
  key := #[ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]

  tag_crypto1 := Crypto1 --key=key
  reader_crypto1 := Crypto1 --key=key

  prng := Crypto1Prng

  uid := #[0xcd, 0x76, 0x92, 0x74]
  n_t := #[0x0e, 0x61, 0x64, 0xD6]

  prng.set_state --bytes=n_t
  prng.shift 64
  a_r := prng.current_bytes
  print "a_r: $a_r"
  prng.shift 32
  a_t := prng.current_bytes
  print "a_t: $a_t"

  xored := ByteArray 4: uid[it] ^ n_t[it]

  xored_value := LITTLE_ENDIAN.uint32 xored 0
  32.repeat:
    tag_crypto1.shift xored_value & 1
    reader_crypto1.shift xored_value & 1
    xored_value >>= 1
  print "$(%x tag_crypto1.lfsr_state_)"

  n_r := #[0x15, 0x45, 0x90, 0xa8]

  print "Reader state: $(%x reader_crypto1.lfsr_state_)"
  print "Tag state:    $(%x tag_crypto1.lfsr_state_)"

  // Encrypt the n_r, but also feed it into the lfsr of the cipher.
  n_r_encrypted := ByteArray n_r.size
  n_r.size.repeat: | index |
    byte := n_r[index]
    8.repeat: | bit_index |
      cipher_bit := reader_crypto1.cipher_bit --should_shift=false
      plain_bit := (byte >> bit_index) & 1
      byte ^= cipher_bit << bit_index
      reader_crypto1.shift plain_bit
    n_r_encrypted[index] = byte

  print "Encrypted n_r: $n_r_encrypted"

  // The tag now gets this encrypted n_r and needs to decrypt it and
  // feed it into its own LFSR.
  // We are discarding the decrypted n_r.

  n_r_encrypted.size.repeat: | index |
    byte := n_r_encrypted[index]
    8.repeat: | bit_index |
      cipher_bit := tag_crypto1.cipher_bit --should_shift=false
      encrypted_bit := (byte >> bit_index) & 1
      decrypted := encrypted_bit ^ cipher_bit
      tag_crypto1.shift decrypted

  // Both states are now the same:
  print "Reader state: $(%x reader_crypto1.lfsr_state_)"
  print "Tag state:    $(%x tag_crypto1.lfsr_state_)"

  // Reader also sends back the encrypted a_r.
  a_r_encrypted := ByteArray a_r.size
  a_r.size.repeat: | index |
    byte := a_r[index]
    8.repeat: | bit_index |
      cipher_bit := reader_crypto1.cipher_bit
      byte ^= cipher_bit << bit_index
    a_r_encrypted[index] = byte

  print "Encrypted a_r: $a_r_encrypted"

  // The tag decrypts the a_r and checks it.
  a_r_decrypted := ByteArray a_r_encrypted.size
  a_r_decrypted.size.repeat: | index |
    byte := a_r_decrypted[index]
    8.repeat: | bit_index |
      cipher_bit := tag_crypto1.cipher_bit
      byte ^= cipher_bit << bit_index
    a_r_decrypted[index] = byte

  print "Decrypted a_r: $a_r_decrypted"

  // The tag sends back the encrypted a_t.
  a_t_encrypted := ByteArray a_t.size
  a_t.size.repeat: | index |
    byte := a_t[index]
    8.repeat: | bit_index |
      cipher_bit := tag_crypto1.cipher_bit
      byte ^= cipher_bit << bit_index
    a_t_encrypted[index] = byte

  print "Encrypted a_t: $a_t_encrypted"

  // Finally, the reader decrypts the a_t.
  a_t_decrypted := ByteArray a_t_encrypted.size
  a_t_decrypted.size.repeat: | index |
    byte := a_t_decrypted[index]
    8.repeat: | bit_index |
      cipher_bit := reader_crypto1.cipher_bit
      byte ^= cipher_bit << bit_index
    a_t_decrypted[index] = byte

  print "Decrypted a_t: $a_t_decrypted"

  // Both states are now the same:
  print "Reader state: $(%x reader_crypto1.lfsr_state_)"
  print "Tag state:    $(%x tag_crypto1.lfsr_state_)"
