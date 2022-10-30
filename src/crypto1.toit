// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

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
- suc² (or suc⁶⁴) corresponds to 64 iterations, and
- suc³ (or suc⁹⁶) to 96 iterations.

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
  the seed was set to 0 when the card started. A tag's nonce was thus dependent on the
  time the authentication was established. (This was one of the earliest attacks).
  TODO(florian): check that this was indeed the case.

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

The reader then constructs a 4-byte challeng n_R. It sends this challenge to the
  tag, using the stream cipher to encrypt it. At the same time, the reader also
  feeds the encrypted challenge into its own LFSR (similar to how n_T⊕u was fed
  into the LFSR).
In the same message, the reader also sends the response to the challenge n_T, which
  which is the suc²(n_T) (that is, the PRNG value after 64 iterations, where the
  seed was n_T). The challenge response is sent encrypted using the normal
  stream cipher.

The tag decrypts the challenge n_R, and feeds the encrypted bits into the LFSR. It
also verifies that the challeng response is correct.
It finishes the authentication by sending suc³(n_R) (that is, the PRNG value
  after 96 iterations) to the reader.

At this stage the cipher has been initialized and both sides share the same LFSR state.
All further messages are encrypted using the output of the filter bits.

The tag finishes the authentication by sending the n_R back to the reader.
*/

class Crypto1:
  static TAPS ::= 0x846B_50D4_1170

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
    lfsr_state_ = (lfsr_state_ << 1) | new_bit

  /**
  Shifts a new bit into the LFSR, xoring it first with the $input bit.
  */
  shift input/int:
    new_bit := (lfsr_state_ & TAPS).parity ^ input
    lfsr_state_ = (lfsr_state_ << 1) | new_bit

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
    print "filter: $result - $v5 $v4 $v3 $v2 $v1 - $(%x v5 << 4 | v4 << 3 | v3 << 2 | v2 << 1 | v1)"
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


// interface ConnectionEncrypter:
//   encrypt --in_place/bool bytes/ByteArray

// class IdentityEncrypter implements ConnectionEncrypter:
//   encrypt --in_place/bool bytes/ByteArray:
//     if not in_place: throw "INVALID_ARGUMENT"
//     return bytes

// class Crypto1Encrypter implements ConnectionEncrypter:
//   crypto1/Crypto1

//   constructor key/ByteArray:
//     crypto1 = Crypto1 --key=key

//   encrypt --in_place/bool bytes/ByteArray:
//     if not in_place: throw "INVALID_ARGUMENT"
//     bytes.size.repeat:

//       bytes[i] ^= crypto1.cipher_bit
//     return bytes

/**
*/
class Crypto1Prng:

main:
  key := #[ 0xd7, 0x96, 0x86, 0x65, 0xfb, 0x36 ]
  endian := 0x0
  key.do: | byte |
    8.repeat:
      endian <<= 1
      endian += byte & 1
      byte >>= 1

  crypto1 := Crypto1 endian
  bits := 0
  63.repeat:
    // print "State: $(%x crypto1.lfsr_state_ & 0xFFFF_FFFF_FFFF) $(%x (crypto1.lfsr_state_) << 1) "
    bits = (bits << 1) | crypto1.cipher_bit
  print "$(%x bits)"
