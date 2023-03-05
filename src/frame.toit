// Copyright (C) 2023 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

import .nfc_exception

/**
An RFID frame.

Depending on the configuration the frame could be raw (where parity bits must be
  handled by the caller) or not.
*/
class Frame:
  bytes/ByteArray
  size_in_bits/int
  is_raw/bool
  /**
  The position of a collision if there was one.

  Can only happen for frames received by the reader.
  */
  collision_position/int?

  /**
  Constructs a new frame with the given $bytes.

  The $size_in_bits is the number of bits in the frame. It does not need to be a multiple of 8.

  The number of bytes must be at least ($size_in_bits + 7) / 8. In other words, there must be
    enough bits in the given $bytes array.
  */
  constructor .bytes --.size_in_bits=(bytes.size * 8) --raw/bool=false --.collision_position=null:
    is_raw = raw

  /**
  Makes this frame a raw frame, where parity bits are included in the $bytes.

  Adds the parity bits to the frame and sets the $is_raw flag.
  */
  to_raw -> Frame:
    if is_raw: return this
    with_parity := insert_parity_bits_ bytes
    bit_size := bit_size_of_bytes_with_parity_ with_parity
    return Frame with_parity --size_in_bits=bit_size --raw=true

  /**
  Makes this frame a non-raw frame, where parity bits are not included in the $bytes.
  */
  to_non_raw --check_parity -> Frame:
    if not is_raw: return this
    without_parity := remove_parity_bits_ bytes --check=check_parity
    return Frame without_parity

  stringify -> string:
    if collision_position:
      return "Frame($size_in_bits bits: $bytes, collision at $collision_position)"
    if is_raw:
      return "Frame($size_in_bits bits: $bytes, raw)"
    return "Frame($size_in_bits bits: $bytes)"

  /**
  Inserts odd parity bits into the given $bytes.

  The result is a byte array that has an additional parity bit for each byte.
  The valid bits of the result can be computed with $bit_size_of_bytes_with_parity_.
  */
  insert_parity_bits_ bytes/ByteArray -> ByteArray:
    if bytes.size == 0: throw "INVALID_ARGUMENT"

    // Add one parity bit per byte.
    result := ByteArray (bytes.size + (bytes.size + 7) / 8)
    target_index := 0
    target_bit_index := 0
    for i := 0; i < bytes.size; i++:
      byte := bytes[i]
      parity := byte.parity ^ 1  // Odd parity.
      result[target_index] |= byte << target_bit_index
      target_index++
      if target_bit_index != 0:
        result[target_index] |= byte >> (8 - target_bit_index)
      result[target_index] |= parity << target_bit_index
      target_bit_index++
      if target_bit_index == 8:
        target_bit_index = 0
        target_index++
    return result

  bit_size_of_bytes_with_parity_ bytes/ByteArray -> int:
    return (bytes.size * 8 / 9) * 9


  /**
  Removes the parity bits from the given $bytes.

  The result is a byte array that has one less bit for each byte.

  If $check is true then the parity bits are checked and an exception is thrown if they are not
    correct.
  */
  remove_parity_bits_ bytes/ByteArray --check/bool=true -> ByteArray:
    result := ByteArray (bytes.size * 8 / 9)
    source_index := 0
    source_bit_index := 0

    for i := 0; i < result.size; i++:
      byte := bytes[source_index] >> source_bit_index
      source_index++
      if source_bit_index != 0:
        byte |= bytes[source_index] << (8 - source_bit_index)
        byte &= 0xFF
      parity_bit := (bytes[source_index] >> source_bit_index) & 1
      source_bit_index++
      if source_bit_index == 8:
        source_index++
        source_bit_index = 0

      if check:
        parity := byte.parity ^ 1  // Odd parity.
        if parity != parity_bit: throw NfcException.parity

      result[i] = byte
    return result
