// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A driver for the MFRC522 RFID reader.
*/

import serial

class RfidException:
  /**
  Error when a device did not respond.

  This can happen if the user requested to wake a specific device, or if
    the anti-collision protocol selected one of two cards, but none responded at
    the next step.
  */
  static NO_RESPONSE ::= 0

  /** A checksum (parity, or CRC) error was detected. */
  static CHECKSUM ::= 1

  /**
  A protocol error was detected.

  A card responded in an unexpected way. Most often, this is actually caused by
    a communication error; for example, when too many cards are in the field.
  */
  static PROTOCOL ::= 2

  /** A timeout was detected. */
  static TIMEOUT_ERROR ::= 3

  /** A collision was detected. */
  static COLLISION ::= 4

  /**
  An internal error was detected.

  If encountered, please file a bug; ideally with a reproducible example.
  */
  static INTERNAL ::= 5

  /**
  The internal temperature sensor detected overheating and shut down the antenna drivers.
  */
  static TEMPERATURE ::= 6

  code/int

  constructor.no_response: code = NO_RESPONSE
  constructor.checksum:    code = CHECKSUM
  constructor.protocol:    code = PROTOCOL
  constructor.timeout:     code = TIMEOUT_ERROR
  constructor.collision:   code = COLLISION
  constructor.internal:    code = INTERNAL
  constructor.temperature: code = TEMPERATURE

  stringify -> string:
    if code == NO_RESPONSE: return "No response from card"
    if code == CHECKSUM: return "Checksum error"
    if code == PROTOCOL: return "Protocol error"
    if code == TIMEOUT_ERROR: return "Timeout"
    if code == COLLISION: return "Collision"
    if code == INTERNAL: return "Internal error"
    if code == TEMPERATURE: return "Temperature error; antenna is off due to overheating"
    unreachable

class Mfrc522:
  static COMMAND_REGISTER_ ::= 0x01 << 1
  static COM_IRQ_REGISTER_ ::= 0x04 << 1
  static ERROR_REGISTER_ ::= 0x06 << 1
  static STATUS_2_REGISTER_ ::= 0x08 << 1
  static FIFO_DATA_REGISTER_ ::= 0x09 << 1
  static FIFO_LEVEL_REGISTER_ ::= 0x0A << 1
  static BIT_FRAMING_REGISTER_ ::= 0x0D << 1
  static COLL_REGISTER_ ::= 0x0E << 1
  static MODE_REGISTER_ ::= 0x11 << 1
  static TX_MODE_REGISTER_ ::= 0x12 << 1
  static RX_MODE_REGISTER_ ::= 0x13 << 1
  static TX_CONTROL_REGISTER_ ::= 0x14 << 1
  static TX_ASK_REGISTER_ ::= 0x15 << 1
  static MOD_WIDTH_REGISTER_ ::= 0x24 << 1
  static T_MODE_REGISTER_ ::= 0x2A << 1
  static T_PRESCALER_REGISTER_ ::= 0x2B << 1
  static T_RELOAD_REGISTER_ ::= 0x2C << 1
  static AUTO_TEST_REGISTER_ ::= 0x36 << 1
  static VERSION_REGISTER_ ::= 0x37 << 1

  static COMMAND_IDLE_ ::= 0x00                // No action, cancels current command
  static COMMAND_MEM_ ::= 0x01                 // Stores 25 bytes into the internal buffer.
  static COMMAND_GENERATE_RANDOM_ID_ ::= 0x02  // Generates a 10-byte random ID number.
  static COMMAND_CALCULATE_CRC_ ::= 0x03       // Activates the CRC coprocessor or performs a self test.
  static COMMAND_TRANSMIT_ ::= 0x04            // Transmits data from the FIFO buffer.
  static COMMAND_NO_CMD_CHANGE_ ::= 0x07       // No command change. Can be used to modify the other bits without affecting the command.
  static COMMAND_RECEIVE_ ::= 0x08             // Activates the receiver circuits.
  static COMMAND_TRANSCEIVE_ ::= 0x0C          // Transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission.
  static COMMAND_MF_AUTHENT_ ::= 0x0E          // Performs the MIFARE standard authentication as a reader.
  static COMMAND_SOFT_RESET_ ::= 0x0F          // Resets the MFRC522.

  registers_ /serial.Registers

  constructor device/serial.Device:
    registers_ = device.registers

  on:
    reset_soft_
    reset_communication_

    // When communicating with a card we need a timeout if something goes wrong.
    // f_timer = 13.56 MHz / (2 * pre_scaler + 1).
    // We pre_scale by a factor of 169, giving us a scaled frequency of ~40kHz, and a timer period of ~25us.
    pre_scaler := 0x0A9
    // Start the timer automatically at the end of a transmission all communication modes at all speeds.
    // The least significant bits store the pre_scaler's high bits.
    t_mode := 0x80 | (pre_scaler >> 8)
    registers_.write_u8 T_MODE_REGISTER_ t_mode
    // The remaining pre_scaler bits are stored in the T_PRESCALER_REGISTER.
    registers_.write_u8 T_PRESCALER_REGISTER_ (pre_scaler & 0xFF)
    reload_ticks := 1000  // Timeout of 1000 * 25us = 25ms.
    registers_.write_u16_be T_RELOAD_REGISTER_ reload_ticks

    // Force a 100% ASK modulation independent of the ModWidth setting.
    // ASK = Amplitude Shift Keying.
    // This is copied from https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.cpp#L239
    // Default: 0x00
    registers_.write_u8 TX_ASK_REGISTER_ 0x40

    // Set the CRC coprocessor parameter to using 0x6363 as CRC preset value.
    // See section 6.1.6 CRC_A of the ISO_IEC_14443-3:2001 specification.
    // Section 9.3.2.2.
    // Default value: 0x3F.
    // CRC-Presets: bits 0-1, with 0b01 setting it to 0x6363.
    registers_.write_u8 MODE_REGISTER_ 0x3D

    // A soft reset turns the antennas off.
    antenna_on

  /**
  Transmits a short frame and returns the response.

  A short frame consists of just 7 bits of data. It doesn't have any CRC or parity bit.

  Common short-frame commands:
  - REQA (0x26): Request any new card to go into IDLE state.
  - WUPA (0x52): Requests any card to go into IDLE state.

  Other values:
  - 0x35: Optional timeslot method. (see Annex C of iso14443-3)
  - 0x40 to 0x4F: Proprietary.
  - 0x78 to 0x7F: Proprietary.
  - all other values: RFU (reserved for future use).

  See section Iso 14443-3 2008; section 6.2.3.1.
  */
  transceive_short_ command/int --allow_collision -> ByteArray?:
    if command >= 0x80: throw "INVALID_ARGUMENT"

    // Send only 7 bits of the last (only) byte.
    set_framing_ --tx_last_bits=7

    return transceive_ #[command] --allow_collision=allow_collision

  /**
  Transmits a standard frame and returns the response.

  Automatically adds the CRC.

  If $check_crc is true, then automatically checks the crc of the response.
  */
  transceive_standard_ bytes/ByteArray --check_crc/bool=false -> ByteArray?:
    crc := compute_crc_ bytes
    bytes += #[crc & 0xFF, (crc >> 8) & 0xFF]

    // Send all 8 bits of the last (only) byte.
    set_framing_ --tx_last_bits=0
    return transceive_ bytes --check_crc=check_crc

  /**
  Transmits an anticollision frame and returns the response.

  An anticollision frame might have only some bits of the last byte that are valid. During
    sending only those last bits are used. During receiving the first bits are shifted as to
    complete the byte.
  */
  transceive_anticollision_ bytes/ByteArray --last_byte_bits/int -> ByteArray?:
    // We want to send only 'tx_last_bits' bits. The remaining bits should be ignored.
    tx_last_bits := last_byte_bits
    // When receiving, the first bit sholud be shifted by 'rx_align' which is the same as the
    // bits w
    rx_align := last_byte_bits

    set_framing_ --rx_align=rx_align --tx_last_bits=tx_last_bits
    return transceive_ bytes --allow_collision

  /**
  Sets the framing for future transmissions.

  The $rx_align parameter is used for handling collisions. It should otherwise always be 0.
    The first received bit is shifted by $rx_align positions. For example, if it is 6, then the
    first 2 received bits are stored as MSB bits of the first byte, and the remaining received bits
    are stored in subsequent bytes.

  The $tx_last_bits parameter defines the number of bits of the last byte that should be transmitted.
    If it is equal to 0, then the whole byte is transmitted. This value is 7 for short frames (since
    they have only 7 data bits), 0 for standard frames, and any value for anticollision frames.
  */
  set_framing_ --rx_align/int=0 --tx_last_bits/int=0:
    if not 0 <= rx_align < 8: throw "INVALID_ARGUMENT"
    if not 0 <= tx_last_bits < 8: throw "INVALID_ARGUMENT"

    // Bit 7: StartSend == 0. (If 1, starts the transmission of data; only valid in
    //     combination with the Transceive command).
    // Bit 6-4: RxAlign. Used for reception of bit-oriented frames.
    //    Usually 0, except for bitwise anticollision at 106bBd.
    //    0: LSB of the received bit is stored at bit position 0; second at position 1.
    //    1: LSB of the received bit is stored at bit position 1; second at position 2.
    //    7: LSB of the received bit is stored at bit position 7; the second received bit is
    //        stored in the next byte that follows a bit position 0.
    // Bit 3: reserved for future use.
    // Bit 2-0: TxLastBits. Used for transmission of bit oriented frames: defines the number of
    //     bits of the last byte that will be transmitted. 0 indicates that all bits should be transmitted.
    registers_.write_u8 BIT_FRAMING_REGISTER_ ((rx_align << 4) | tx_last_bits)

  transceive_ bytes/ByteArray --command/int=COMMAND_TRANSCEIVE_ --allow_collision/bool=false --check_crc/bool=false -> ByteArray?:
    // The FIFO can handle up to 64 bytes.
    if bytes.size > 64: throw "INVALID_ARGUMENT"
    // Cancel any existing command.
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_IDLE_

    // Clear all irq bits.
    // The MSB of the register is 0, indicating that all marked bits are cleared.
    registers_.write_u8 COM_IRQ_REGISTER_ 0x7F

    // Flush the FIFO buffer.
    // "Immediately clears the internal FIFO buffer's read and write pointer and ErrorReg register's BufferOvfl bit."
    registers_.write_u8 FIFO_LEVEL_REGISTER_ 0x80

    // Write the data into the FIFO.
    registers_.write_bytes FIFO_DATA_REGISTER_ bytes

    // Send the command.
    registers_.write_u8 COMMAND_REGISTER_ command

    if command == COMMAND_TRANSCEIVE_:
      // Execute the transceive.
      // 9.3.1.14:
      //   Bit 7: StartSend: If 1, starts the transmission of data; only valid in
      //       combination with the Transceive command.
      registers_.write_u8 BIT_FRAMING_REGISTER_ (registers_.read_u8 BIT_FRAMING_REGISTER_) | 0x80

    // Wait for the response:
    completed := false
    // TODO(florian): make sure timing is correct.
    for i := 0; i < 10; i++:
      irqs := registers_.read_u8 COM_IRQ_REGISTER_
      // Irq bits:
      // 7: Set1. When writing defines whether the masked bits should be set or cleared.
      // 6: TxIRq. Set immediately after the last bit of the transmitted data was sent out.
      // 5: RxIRq. Receiver has detected the end of a valid data stream. Note: RxModeReg can influence behavior.
      // 4: IdleIRq. If a command terminates, for example, when the CommandReq changes its value
      //    from any command to the Idle command. If an unknown command is started.
      //    The microcontroller starting the Idle command does not set the IdleIRq bit.
      // 3: HiAlertIRq. Status1Reg has HiAlert bit set.
      // 2. LoAlertIRq. Status1Reg has LoAlert bit set.
      // 1. ErrIRq. any error bit in the ErrorReg register is set.
      // 0. TimerIRq: the timer decrements the timer value in register TCounterValReg to zero.

      // Rx and Idle. (Not sure why idle).
      if irqs & 0x30 != 0:
        completed = true
        break
      // Timeout. Remember that we automatically start the timeout due to the initialization
      // in the $on function.
      if (irqs & 0x01) != 0:
        throw RfidException.timeout
      sleep --ms=3

    if not completed: return null

    error := registers_.read_u8 ERROR_REGISTER_
    /*
    Section 9.3.1.7. Table 34.
    * Bit 7 - WrErr: data is written into the FIFO buffer by the host at an invalid point in time.
    * Bit 6 - TempErr: internal temperature sensor detects overheating, in which case the antenna drivers are
        automatically turned off.
    * Bit 5 - reserved.
    * Bit 4 - BufferOvfl: the host (or the MFRC522's internal state machine) tries to write data into to
        FIFO even though it's already full.
    * Bit 3 - CollErr: collision error. The MFRC522's internal state machine detected a collision.
    * Bit 2 - CRCErr: CRC error. The CRC check of the received data failed.
    * Bit 1 - ParityErr: parity error. The received data has an invalid parity.
    * Bit 0 - ProtocolErr: SOF is incorrect. (Used for MFAuthent).
    */

    detected_collision := error & 0x08 != 0
    if detected_collision and not allow_collision:
      throw RfidException.collision
    if detected_collision:
      // Ignore parity errors. They might be caused by the collision.
      error &= ~0x02

    // For bit 7 and 4 something is writing even though it shouldn't.
    if error & 0x80 != 0 or error & 0x10 != 0: throw RfidException.internal
    if error & 0x40 != 0:                      throw RfidException.temperature
    if error & 0x04 != 0 or error & 0x02 != 0: throw RfidException.checksum
    if error & 0x01 != 0:                      throw RfidException.protocol

    response_size := registers_.read_u8 FIFO_LEVEL_REGISTER_
    // We must not use `read_bytes` for SPI. That doesn't yield the correct result.
    result := ByteArray response_size: registers_.read_u8 FIFO_DATA_REGISTER_

    if check_crc:
      check_crc_ result
      return result[..result.size - 2]
    return result

  /**
  Computes the CRC as required by the ISO 14443-3 standard.

  The chip actually has a hardware based CRC, but it's almost certainly faster to just do it here.
  */
  compute_crc_ data/ByteArray -> int:
    // Specification 6.2.4 CRC_A.
    // Also see Appendix B.
    // Initial register shall be 0x6363.
    // The polynomial is from ISO/IEC 13239: 0x8408
    crc := 0x6363
    data.size.repeat:
      crc = crc ^ data[it]
      8.repeat:
        if (crc & 1) != 0:
          crc = (crc >> 1) ^ 0x8408
        else:
          crc >>= 1
    return crc

  check_crc_ data/ByteArray:
    if data.size < 3: throw RfidException.protocol
    crc := compute_crc_ data[..data.size - 2]
    if crc & 0xFF != data[data.size - 2] or crc >> 8 != data[data.size - 1]:
      throw RfidException.checksum

  /**
  Executes an anticollision to get the UID of a PICC in the field.

  The cascade-level is encoded in the $command.
  The $uid_buffer must be 4 bytes long and correspond to the current cascade level.

  Returns when the $uid_buffer is filled.
  */
  cascade_get_uid_ command/int uid_buffer/ByteArray -> none:
      assert: uid_buffer.size == 4

      known_bits := 0

      // Complete this cascade level.
      // That is, iterate until we have a unique UID for this cascade level.
      // We might iterate this loop 32 times because of a collision for each bit.
      while true:
        index := 0
        // The biggest outbound frame consists of 6 bytes:
        // - 1 byte command.
        // - 1 byte valid bytes/bits.
        // - 4 bytes of UID (potentially the first one being a Cascade Tag, indicating that the UID needs
        //          an additional cascade level).
        bytes := ByteArray 6
        bytes[index++] = command

        // Fully valid uid bytes.
        valid_uid_bytes := known_bits / 8
        // Additional valid bits.
        valid_bits := known_bits % 8

        // The valid bits are encoded with the higher nible containing the amount of fully valid bytes, and the
        // the lower nibble containing the remaining bits.
        // The encoded value includes the select-command and the valid-bits byte.
        // If this is a full select (all bits are known), the value is updated below.
        encoded_valid_bits := ((valid_uid_bytes + 2) << 4) + valid_bits
        bytes[index++] = encoded_valid_bits

        to_copy := valid_bits == 0 ? valid_uid_bytes : valid_uid_bytes + 1
        for i := 0; i < to_copy; i++:
          bytes[index++] = uid_buffer[i]

        // Request the PICCs to complete the ID and watch for collisions.
        response := transceive_anticollision_ bytes[..index] --last_byte_bits=valid_bits
        if not response: throw RfidException.no_response

        // The PICC is supposed to complete the UID and add a checksum (BCC).
        if response.size + valid_uid_bytes != 5:
          throw RfidException.protocol

        // We start by assuming that the response is without collision. If there was one, we will
        // fix that later.
        uid_pos := valid_uid_bytes
        response_index := 0
        if valid_bits != 0:
          half_byte := response[response_index]
          uid_buffer[uid_pos] &= (1 << valid_bits) - 1  // Clear the bits that were unknown.
          uid_buffer[uid_pos] |= half_byte
          uid_pos++
          response_index++
        while uid_pos < 4:
          uid_buffer[uid_pos++] = response[response_index++]

        error := registers_.read_u8 ERROR_REGISTER_
        detected_collision := error & 0x08 != 0
        if not detected_collision:
          bcc := uid_buffer[0] ^ uid_buffer[1] ^ uid_buffer[2] ^ uid_buffer[3]
          if bcc != response[response_index]: throw RfidException.checksum
          return

        collision_value := registers_.read_u8 COLL_REGISTER_
        has_valid_collision_position := (collision_value & 0x20) == 0
        if not has_valid_collision_position:
          // Collision detected, but without any valid position.
          // Give up.
          throw RfidException.internal

        collision_position := collision_value & 0x1F
        // If the collision position is 0, then the collision happened at bit 32.
        // See MFRC522 - 9.3.1.15, table 50.
        if collision_position == 0: collision_position = 32
        if collision_position <= known_bits: throw "STATE_ERROR"
        if collision_position + known_bits > 32: throw "STATE_ERROR"
        // Up to the collision position the bits were received correctly.
        // At the collision point we now have to choose which branch we want to follow.
        // We arbitrarily pick the one that we already wrote into the uid_buffer, and just
        // state that this bit is now a known bit.
        known_bits += collision_position

  /**
  Transceives the select for this cascade level.

  Returns the received SAK (select acknowledge).
  */
  cascade_select_ command/int uid_buffer/ByteArray -> ByteArray:
    // The frame frame consists of 9 bytes:
    // - 1 byte command.
    // - 1 byte valid bytes/bits. Since all bits are valid, always equal to 0x70.
    // - 4 bytes of UID (potentially the first one being a Cascade Tag, indicating that the UID needs
    //          an additional cascade level).
    // - 1 byte of BCC (Block Check Character).
    // - 2 bytes of CRC. These will be added by the `transceive_standard_` function.
    bytes := ByteArray 7

    bytes[0] = command

    // 7 bytes, since we also send the BCC.
    // The CRC is not counted.
    bytes[1] = 0x70

    bytes.replace 2 uid_buffer

    // We know all bits for this level.
    // This is a "select" call, and not an anti-collision frame.
    // A select also needs the BCC and the CRC.
    bcc := bytes[2] ^ bytes[3] ^ bytes[4] ^ bytes[5]
    bytes[6] = bcc
    response := transceive_standard_ bytes --check_crc

    if not response: throw RfidException.no_response
    // The SAK must be exactly 1 bytes long (once the CRC has been removed).
    if response.size != 1: throw RfidException.protocol
    return response

  /**
  Selects one of the woken PICCs.

  PICCs can be woken either by sending a REQA or WUPA. See $(do --new [block]) and $with_picc.
  */
  select_ uid/ByteArray=#[] -> Card:
    // Section 6.5.3.1
    // A UID is either 4, 7, or 10 bytes long.
    // A cascade level has only space for 4 bytes of payload.
    // If the UID is 4 bytes long, we can just send it in the first cascade.
    // If it's longer, we use the cascade tag as first byte of the payload to
    // indicate that another cascade level follows. The same is true for the second cascade level.
    // If it's 7 bytes long, we already sent 3 bytes in the first cascade, and can use the remaining
    // 4 bytes for the rest. Otherwise, we send again a cascade tag, followed by the next 3 bytes.
    //
    // Note that the cascade tag is not a valid byte at 0'th and 4'th position to avoid ambiguity.
    //
    // When sending a select command we send as much of the UID as we already know. All
    // PICCs that fit the (partial) UID respond with the rest of the UID. The PCD then detects
    // collisions, and we arbitrarily pick one of the colliding PICCs.
    // Over time we end up increasing the amount of known bits.
    CASCADE_TAG ::= 0x88

    SELECT_CASCADE1 ::= 0x93  // 4 byte UID.
    SELECT_CASCADE2 ::= 0x95  // 7 byte UID.
    SELECT_CASCADE3 ::= 0x97  // 10 byte UID.

    // Create a uid-buffer which represents more closely what we actually send.
    // If we don't have any UID, also make sure we have space to write for the received data.
    uid_buffer/ByteArray := ?
    if uid.size == 0: uid_buffer = ByteArray 12
    else if uid.size == 4: uid_buffer = uid
    else if uid.size == 7: uid_buffer = #[CASCADE_TAG] + uid
    else if uid.size == 10:
      uid_buffer = #[CASCADE_TAG] + uid[0..3] + #[CASCADE_TAG] + uid[3..]
    else:
      throw "INVALID_ARGUMENT"

    // We can now send the chunks nicely, 4 bytes each.
    assert: uid_buffer.size % 4 == 0

    // The known bits, including cascade tags, of the UID.
    known_bits := uid.size == 0 ? 0 : uid_buffer.size * 8

    // C code clears bits received after a collision.
    // Don't think we need that.
    // PCD_ClearRegisterBitMask(CollReg, 0x80);
    // registers_.write_u8 COLL_REGISTER_ ((registers_.read_u8 COLL_REGISTER_) & 0x7F)

    // Go through the different cascade levels.
    // If the ID is shorter we break out of the loop.
    for cascade_level := 1; cascade_level <= 3; cascade_level++:
      command /int := ?
      if cascade_level == 1: command = SELECT_CASCADE1
      else if cascade_level == 2: command = SELECT_CASCADE2
      else: command = SELECT_CASCADE3

      cascade_uid_buffer := uid_buffer[(cascade_level - 1) * 4 .. cascade_level * 4]

      // Unless we already have the UID, perform an anticollision to get one UID in the field.
      if uid.size == 0:
        cascade_get_uid_ command cascade_uid_buffer

      // Select acknowledge.
      sak := cascade_select_ command cascade_uid_buffer

      // 6.5.3.4: if b3 is set then the UID is not complete.
      needs_another_cascade := sak[0] & 0x04 != 0

      if needs_another_cascade:
        if cascade_level == 3: throw RfidException.protocol
        continue

      // Remove the cascade tags.
      if cascade_level == 1: uid = uid_buffer[0..4].copy
      else if cascade_level == 2: uid = uid_buffer[1..8].copy
      else: uid = uid_buffer[1..4] + uid_buffer[5..]

      return Card this uid sak[0]

    unreachable

  is_authenticated_ -> bool:
    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. Indicates that the MIFARE Crypto1 unit is switched on.
    return (registers_.read_u8 STATUS_2_REGISTER_) & 0x08 != 0

  // TODO(florian): add support for key B.
  authenticate_ --block/int --key/ByteArray --uid/ByteArray --is_key_a/bool -> bool:
    if uid.size != 4 and uid.size != 7 and uid.size != 10: throw "INVALID_ARGUMENT"
    if key.size != 6: throw "INVALID_ARGUMENT"

    // See MIFARE Classic EV1 1K spec.
    // https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
    // Section 9.1.
    AUTHENT_KEY_A_COMMAND ::= 0x60
    AUTHENT_KEY_B_COMMAND ::= 0x61

    // Section 10.3.1.9. MFAuthent of MFRC522 datasheet.
    // 12 bytes need to be written into the FIFO:
    // - Authentication command code (60h, 61h), selecting key A or B.
    // - Block address
    // - 6 sector key bytes.
    // - 4 card serial number bytes.
    bytes := ByteArray 12
    bytes[0] = is_key_a ? AUTHENT_KEY_A_COMMAND : AUTHENT_KEY_B_COMMAND
    bytes[1] = block
    bytes.replace 2 key
    // Fill in the last 4 bytes of the UID.
    // See section 3.2.5 of AN10927.
    // See section 10.1.3 of MIFARE Classic EV1 1K spec.
    bytes.replace 8 uid[uid.size - 4  ..]

    result := transceive_ --command=COMMAND_MF_AUTHENT_ bytes
    return result != null

  stop_crypto_:
    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. When this bit is cleared then the crypto1 is turned off.
    old := registers_.read_u8 STATUS_2_REGISTER_
    registers_.write_u8 STATUS_2_REGISTER_ (old & ~0x08)

  wake_up_cards_ --only_new/bool=false -> ByteArray?:
    reset_communication_

    // Wake up the given PICC.
    // ISO 14443-3
    CMD_WUPA ::= 0x52
    // Wake up new cards.
    // The CMD_REQA should be sent in a "short frame" which has only 7 bits.
    // Iso-14443-3, 6.4.1. "The REQA and WUPA commands [..] are transmitted within a short frame".
    CMD_REQA ::= 0x26

    command := only_new ? CMD_REQA : CMD_WUPA

    // The CMD_REQA/CMD_WUPA should be sent in a "short frame" which has only 7 bits.
    // Iso-14443-3, 6.4.1. "The REQA and WUPA commands [..] are transmitted within a short frame".
    return transceive_short_ command --allow_collision

  /**
  Wakes up all new PICCs and executes the given $block for each.

  The $block is called with the UID of the PICC as argument.
  */
  do --new/bool [block] -> none:
    if not new: throw "INVALID_ARGUMENT"

    while true:
      if not wake_up_cards_ --only_new: return
      card := select_
      try:
        block.call card
      finally:
        card.close

  /**
  Wakes up all cards and selects the card with the given $uid. Then executes the given $block.

  The $block is called with the $Card as argument.
  */
  with_picc uid/ByteArray [block] -> none:
    if not wake_up_cards_: return
    card := select_ uid
    try:
      block.call card
    finally:
      card.close

  antenna_on:
    current := registers_.read_u8 TX_CONTROL_REGISTER_
    if current & 0x03 == 0x03: return
    registers_.write_u8 TX_CONTROL_REGISTER_ (current | 0x03)

  antenna_off:
    current := registers_.read_u8 TX_CONTROL_REGISTER_
    if current & 0x03 != 0x03: return
    registers_.write_u8 TX_CONTROL_REGISTER_ (current & ~0x03)

  reset_soft_:
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_SOFT_RESET_
    // The datasheet doesn't say how long the soft reset takes.
    // The MFRC522 might have been in soft power-down mode, which would take 1024 clock cycles until the
    // mode is exited. In theory we should be able to observe this by looking at the command register. Also,
    // when waking up from this mode, we must take into account that the oscillator takes time to become
    // stable (see the remark in section 8.6.2).
    // According to section 8.8, the oscillator start-up time is the startup-time of the crystal + 37.74us.
    sleep --ms=50
    // Make sure that we are not still waking up from soft power-down mode.
    count := 0
    COMMAND_STATUS_POWER_DOWN_BIT_ ::= 0x10
    while count++ < 3 and (registers_.read_u8 COMMAND_REGISTER_) & COMMAND_STATUS_POWER_DOWN_BIT_ != 0:
      sleep --ms=50

  /**
  Resets the communication configuration.

  Some cards can communicate at different speeds, and might have changed the configurations.
  Resets the baud rate and modulation width to their default values.
  */
  reset_communication_:
    // Reset baud rates.
    registers_.write_u8 TX_MODE_REGISTER_ 0x00
    registers_.write_u8 RX_MODE_REGISTER_ 0x00
    // Reset ModWidthReg.
    registers_.write_u8 MOD_WIDTH_REGISTER_ 0x26

    // Section 9.3.1.9.
    // Bit 3: MFCrypto1On. When this bit is cleared then the crypto1 is turned off.
    old := registers_.read_u8 STATUS_2_REGISTER_
    registers_.write_u8 STATUS_2_REGISTER_ (old & ~0x08)

  /**
  Performs a self test.

  Checks that the self-test data corresponds to one of the $accepted $SelfTestData values.
  */
  self_test --accepted/List=[ SelfTestData.MFRC522_V0_0, SelfTestData.MFRC522_V1_0, SelfTestData.MFRC522_V2_0, SelfTestData.FM17522 ]:
    // Follows the steps outlined in the datasheet, section 16.1.1.

    // 1. Soft Reset
    reset_soft_

    // 2. Clear the buffers and commit to memory.
    zeroes := ByteArray 25: 0x00
    // Clear the fifo.
    registers_.write_u8 FIFO_LEVEL_REGISTER_ 0x80
    registers_.write_bytes FIFO_DATA_REGISTER_ zeroes
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_MEM_

    // 3. Enable the self test by writing 09h to the AutoTestReg register.
    registers_.write_u8 AUTO_TEST_REGISTER_ 0x09

    // 4. Write 00h to FIFO buffer.
    registers_.write_u8 FIFO_DATA_REGISTER_ 0x00

    // 5. Start self test with the CalcCRC command.
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_CALCULATE_CRC_

    // 6. The self test is initiated.
    // 7. When the self test has completed, the FIFO buffer contains the following 64 bytes:

    for i := 0; i < 10; i++:
      level := registers_.read_u8 FIFO_LEVEL_REGISTER_
      if level == 64: break
      sleep --ms=100

    // Stop the CRC command.
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_IDLE_

    // Read out the 64 bytes from the FIFO buffer.
    bytes := ByteArray 64: registers_.read_u8 FIFO_DATA_REGISTER_

    // Reset the AUTO_TEST_REGISTER_ to 0, so normal operation can resume.
    registers_.write_u8 AUTO_TEST_REGISTER_ 0x00
    version := registers_.read_u8 VERSION_REGISTER_

    accepted.do:
      self_test_data/SelfTestData := it
      if version == self_test_data.version and bytes == self_test_data.bytes: return

    throw "Self test failed; unknown self-test data: $version $bytes"

/**
Firmware data for self-tests.
*/
class SelfTestData:

  /**
  Self-test data for MFRC522, version 0.0.

  Version 0.0 (0x90)
  Philips Semiconductors; Preliminary Specification Revision 2.0 - 01 August 2005; 16.1 self-test.
  Copied from: https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.h#L31
  */
  static MFRC522_V0_0 ::= SelfTestData 0x90
    #[
      0x00, 0x87, 0x98, 0x0f, 0x49, 0xFF, 0x07, 0x19,
      0xBF, 0x22, 0x30, 0x49, 0x59, 0x63, 0xAD, 0xCA,
      0x7F, 0xE3, 0x4E, 0x03, 0x5C, 0x4E, 0x49, 0x50,
      0x47, 0x9A, 0x37, 0x61, 0xE7, 0xE2, 0xC6, 0x2E,
      0x75, 0x5A, 0xED, 0x04, 0x3D, 0x02, 0x4B, 0x78,
      0x32, 0xFF, 0x58, 0x3B, 0x7C, 0xE9, 0x00, 0x94,
      0xB4, 0x4A, 0x59, 0x5B, 0xFD, 0xC9, 0x29, 0xDF,
      0x35, 0x96, 0x98, 0x9E, 0x4F, 0x30, 0x32, 0x8D,
    ]

  /**
  Self-test data for MFRC522, version 1.0.

  Version 1.0 (0x91)
  MFRC522, Product data sheet, rev. 3.9 - 27 April 2016; 16.1.1 self-test.
  */
  static MFRC522_V1_0 ::= SelfTestData 0x91
    #[
      0x00, 0xC6, 0x37, 0xD5, 0x32, 0xB7, 0x57, 0x5C,
      0xC2, 0xD8, 0x7C, 0x4D, 0xD9, 0x70, 0xC7, 0x73,
      0x10, 0xE6, 0xD2, 0xAA, 0x5E, 0xA1, 0x3E, 0x5A,
      0x14, 0xAF, 0x30, 0x61, 0xC9, 0x70, 0xDB, 0x2E,
      0x64, 0x22, 0x72, 0xB5, 0xBD, 0x65, 0xF4, 0xEC,
      0x22, 0xBC, 0xD3, 0x72, 0x35, 0xCD, 0xAA, 0x41,
      0x1F, 0xA7, 0xF3, 0x53, 0x14, 0xDE, 0x7E, 0x02,
      0xD9, 0x0F, 0xB5, 0x5E, 0x25, 0x1D, 0x29, 0x79,
    ]

  /**
  Self-test data for MFRC522, version 2.0.

  Version 2.0 (0x92)
  MFRC522, Product data sheet, rev. 3.9 - 27 April 2016; 16.1.1 self-test.
  */
  static MFRC522_V2_0 ::= SelfTestData 0x92
    #[
      0x00, 0xEB, 0x66, 0xBA, 0x57, 0xBF, 0x23, 0x95,
      0xD0, 0xE3, 0x0D, 0x3D, 0x27, 0x89, 0x5C, 0xDE,
      0x9D, 0x3B, 0xA7, 0x00, 0x21, 0x5B, 0x89, 0x82,
      0x51, 0x3A, 0xEB, 0x02, 0x0C, 0xA5, 0x00, 0x49,
      0x7C, 0x84, 0x4D, 0xB3, 0xCC, 0xD2, 0x1B, 0x81,
      0x5D, 0x48, 0x76, 0xD5, 0x71, 0x61, 0x21, 0xA9,
      0x86, 0x96, 0x83, 0x38, 0xCF, 0x9D, 0x5B, 0x6D,
      0xDC, 0x15, 0xBA, 0x3E, 0x7D, 0x95, 0x3B, 0x2F,
    ]

  /**
  Self-test data for FM17522.
  This is a clone from Fudan Semiconductor.
  Copied from: https://github.com/miguelbalboa/rfid/blob/b2ff919438c2c2924092de8348b19049359dddd0/src/MFRC522.h#L67
  */
  static FM17522 ::= SelfTestData 0x88
    #[
      0x00, 0xD6, 0x78, 0x8C, 0xE2, 0xAA, 0x0C, 0x18,
      0x2A, 0xB8, 0x7A, 0x7F, 0xD3, 0x6A, 0xCF, 0x0B,
      0xB1, 0x37, 0x63, 0x4B, 0x69, 0xAE, 0x91, 0xC7,
      0xC3, 0x97, 0xAE, 0x77, 0xF4, 0x37, 0xD7, 0x9B,
      0x7C, 0xF5, 0x3C, 0x11, 0x8F, 0x15, 0xC3, 0xD7,
      0xC1, 0x5B, 0x00, 0x2A, 0xD0, 0x75, 0xDE, 0x9E,
      0x51, 0x64, 0xAB, 0x3E, 0xE9, 0x15, 0xB5, 0xAB,
      0x56, 0x9A, 0x98, 0x82, 0x26, 0xEA, 0x2A, 0x62,
    ]

  version/int
  bytes/ByteArray

  constructor .version .bytes:

/**
An RFID card.

Also known as "PICC" ("Proximity Inductive Coupling Card").
*/
class Card:
  /** Unknown type of card. */
  static TYPE_UNKNOWN	::= 0

  /** MIFARE Ultralight or Ultralight C. */
  static TYPE_MIFARE_UL ::= 1
  /** MIFARE Classic protocol, 320 bytes. */
  static TYPE_MIFARE_MINI ::= 2
  /** MIFARE Classic protocol, 1KB. */
  static TYPE_MIFARE_1K	::= 3
  /** MIFARE Classic protocol, 4KB. */
  static TYPE_MIFARE_4K ::= 4
  /** MIFARE Plus (2KB or 4KB) or MIFARE DESFire */
  static TYPE_MIFARE_PLUS_DESFIRE ::= 5

  /** The UID of this card. */
  uid/ByteArray
  // The proximity coupling device (aka "transceiver").
  transceiver_/Mfrc522
  sak_/int
  is_closed/bool := false

  constructor transceiver/Mfrc522 uid/ByteArray sak/int:
    if sak & 0x08 != 0: return MifareCard transceiver uid sak
    return Card.private_ transceiver uid sak

  constructor.private_ .transceiver_ .uid .sak_:

  /** Whether this card is ISO-14443-4 compliant. */
  is_iso_14443_4_compliant -> bool:
    return sak_ & 0b00100100 == 0b00100000

  /** Whether this card is ISO-18092 (NFC) compliant. */
  is_iso_18092_compliant -> bool:
    return sak_ & 0b01000100 == 0b01000100

  /**
  The type of this card.

  Note that MIFARE Plus cards might report themselves as generic cards for privace reasons.
  */
  type -> int: return sak_to_type_ sak_ uid

  /**
  Transmits the given $bytes as standard frame to the card.

  Returns the response from the card.
  */
  transceive bytes/ByteArray --check_crc/bool=false -> ByteArray?:
    return transceiver_.transceive_standard_ bytes --check_crc=check_crc

  halt_ -> none:
    hlta := #[0x50, 0x00]
    // The transceive will wait for a response, timing out.
    // However, that's not a bad thing to do anyway, as we should give the PICC time to
    // go into HALT state.
    transceiver_.transceive_standard_ hlta

  /**
  Sends a HLTA ('halt' of type A) command to the card.
  */
  close -> none:
    halt_

  static sak_to_type_ sak/int uid/ByteArray -> int:
    // See NXP AN 10833 - MIFARE Type ID Procedure.
    type_bits := sak & 0x7F
    if type_bits == 0x00: return TYPE_MIFARE_UL
    if type_bits == 0x09: return TYPE_MIFARE_MINI
    if type_bits == 0x08: return uid.size == 4 ? TYPE_MIFARE_1K : TYPE_MIFARE_PLUS_DESFIRE
    if type_bits == 0x18: return uid.size == 4 ? TYPE_MIFARE_4K : TYPE_MIFARE_PLUS_DESFIRE
    if type_bits == 0x10: return TYPE_MIFARE_PLUS_DESFIRE
    if type_bits == 0x11: return TYPE_MIFARE_PLUS_DESFIRE
    if type_bits == 0x20: return TYPE_MIFARE_PLUS_DESFIRE
    return TYPE_UNKNOWN

  static type_to_str_ t/int -> string:
    if t == TYPE_UNKNOWN: return "Unknown card"
    if t == TYPE_MIFARE_MINI: return "MIFARE Mini, 320 bytes"
    if t == TYPE_MIFARE_1K: return "MIFARE 1KB"
    if t == TYPE_MIFARE_4K: return "MIFARE 4KB"
    if t == TYPE_MIFARE_PLUS_DESFIRE: return "MIFARE Plus or DESFire"
    if t == TYPE_MIFARE_UL: return "MIFARE Ultralight or Ultralight C"
    unreachable

  stringify -> string:
    uid_str := ""
    uid.do: uid_str += "$(%02x it)"
    return "UID: $uid_str - $(type_to_str_ type)"

// https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
class MifareCard extends Card:
  /**
  The first block of a Mifare card contains the manufacturer data.
  It is generally read-only (except for "magic" cards), and contains:
  -
  */
  static MANUFACTURER_BLOCK ::= 0

  static MIFARE_READ_ ::= 0x30
  static MIFARE_WRITE_ ::= 0xA0
  static ACK_ ::= #[0x0A]

  /** Default key for Mifare cards. */
  static DEFAULT_KEY := #[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

  constructor transceiver/Mfrc522 uid/ByteArray sak/int:
    super.private_ transceiver uid sak

  authenticate --block/int key/ByteArray=DEFAULT_KEY --is_key_a/bool=true:
    return transceiver_.authenticate_ --uid=uid --block=block --key=key --is_key_a=is_key_a

  is_authenticated -> bool:
    return transceiver_.is_authenticated_

  read --block/int:
    if not 0 <= block <= total_block_count: throw "INVALID_ARGUMENT"
    bytes := #[ MIFARE_READ_, block]
    return transceive bytes --check_crc

  /**
  Writes $bytes to a given block.

  Checks that the data is valid for block 0 (the UUID), that the sector trailer's access
    bits are correct, and that they don't lock out the user from modifying the access
    bits in the future.
  If $force is true, writes the data, without doing any check.
  If $force_lockout is true, verifies that the data is correct, but allows to
    lock out the user from modifying the access bits in the future. The parameter
    $force implies $force_lockout.
  */
  write --block/int bytes/ByteArray --force/bool=false --force_lockout/bool=false -> none:
    if not 0 <= block <= total_block_count: throw "INVALID_ARGUMENT"
    if bytes.size != 16: throw "MifareCard.write: bytes must be 16 bytes long"
    if block == MANUFACTURER_BLOCK and not force: check_manufacturer_data_ bytes
    if is_trailer_block block and not force: check_trailer_data_ bytes --allow_lockout=(not force_lockout)

    response := transceive #[ MIFARE_WRITE_, block ]
    if response != ACK_: throw (MifareException.from_response response)
    response = transceive bytes
    if response != ACK_: throw (MifareException.from_response response)

  close -> none:
    // Call halt first, before we reset the authentication.
    super
    transceiver_.stop_crypto_

  is_trailer_block block/int:
    if block < (32 * 4):
      return block % 4 == 3
    return block % 16 == 15

  is_first_block_in_sector block/int:
    if block < (32 * 4):
      return block % 4 == 0
    return block % 16 == 0

  sectors_count -> int:
    if type == Card.TYPE_MIFARE_MINI:
      return 5
    else if type == Card.TYPE_MIFARE_1K or type == Card.TYPE_MIFARE_PLUS_DESFIRE:
      return 16
    else if type == Card.TYPE_MIFARE_4K:
      return 40
    throw "Unknown card"

  total_block_count -> int:
    sectors := sectors_count
    if sectors <= 32: return sectors * 4
    return 32 * 4 + (sectors - 32) * 16

  /**
  The size of the given block in blocks.
  */
  sector_size_in_blocks sector/int -> int:
    if sector < 32: return 4
    return 16

  /**
  Extracts the access bits from the trailer block.

  The returned list contains 4 integers, each between 0 and 7.
  The first three integers provide the access bits for the data blocks.
  The list integer provides the access bits for the trailer block itself.

  When a sector has more than 3 data blocks (Mifare 4K), then the access bits are
    applied as follows:
    * b0 (the first byte), applies to blocks 0-4
    * b1 (the second byte), applies to blocks 5-9
    * b2 (the third byte), applies to blocks 10-14

  The meaning of the access bits for data blocks is as follows:
  ```
          read write increment decrement/transfer/restore
  0b000:   AB   AB      AB       AB    # Transport configuration
  0b010:   AB   --      --       --    # read/write block
  0b100:   AB    B      --       --    # read/write block
  0b110:   AB    B       B       AB    # value block
  0b001:   AB   --      --       AB    # value block
  0b011:    B    B      --       --    # read/write block
  0b101:    B   --      --       --    # read/write block
  0b111:   --   --      --       --    # read/write block
  ```

  The meaning of the access bits for the trailer block is as follows.
  ```
          Key A, Access bits, Key B
  0b000: Aw   ,  Ar        , Arw      # Key B is readable.
  0b010:      ,  Ar        , Ar       # Key B is readable.
  0b100:    Bw,  Ar  Br    ,     Bw
  0b110:      ,  Ar  Br    ,
  0b001: Aw   ,  Arw       , Arw      # Transport configuration. Key B is readable.
  0b011:    Bw,  Ar  Brw   ,     Bw
  0b101:      ,  Ar  Brw   ,
  0b111:      ,  Ar  Br    ,
  ```
  */
  static access_bits_from_trailer bytes/ByteArray -> List:
    if bytes.size != 16: throw "MifareCard.access_bits_from_trailer: bytes must be 16 bytes long"
    c1 := bytes[7] >> 4
    c2 := bytes[8] & 0xf
    c3 := bytes[8] >> 4
    c1_ := bytes[6] & 0xf
    c2_ := bytes[6] >> 4
    c3_ := bytes[7] & 0xf

    // cX_ should always be the inverted version of cX.
    if c1_ != 0xf - c1 or c2_ != 0xf - c2 or c3_ != 0xf - c3:
      throw (MifareException.from_code MifareException.INVALID_ACCESS_BITS)
    else:
      b0 := (c1 & 0b0001) << 2 | (c2 & 0b0001) << 1 | (c3 & 0b0001) << 0
      b1 := (c1 & 0b0010) << 1 | (c2 & 0b0010) << 0 | (c3 & 0b0010) >> 1
      b2 := (c1 & 0b0100) << 0 | (c2 & 0b0100) >> 1 | (c3 & 0b0100) >> 2
      b3 := (c1 & 0b1000) >> 1 | (c2 & 0b1000) >> 2 | (c3 & 0b1000) >> 3
      return [b0, b1, b2, b3]

  check_keys_ keys/List:
    keys.do:
      if it.size != 6: throw "Keys must be 6 bytes long"

  dump --keys/List=(List sectors_count: DEFAULT_KEY) -> ByteArray:
    check_keys_ keys
    result := ByteArray total_block_count * 16
    sector_counter := 0
    key/ByteArray? := null
    for i := 0; i < total_block_count; i++:
      if is_first_block_in_sector i:
        // Set the key so we can update the trailer block later.
        key = keys[sector_counter]
        authenticated := authenticate --block=i key
        if not authenticated: throw (MifareException.from_code MifareException.AUTHENTICATION_FAILED)
        sector_counter++
      block_bytes := read --block=i
      if is_trailer_block i: block_bytes.replace 0 key
      result.replace (i * 16) block_bytes
    return result

  static data_access_bits_to_string bits/int -> string:
    if bits == 0b000:
      return "000 - read:AB, write:AB, increment:AB, decrement:AB"
    if bits == 0b010:
      return "010 - read:AB"
    if bits == 0b100:
      return "100 - read:AB, write:B"
    if bits == 0b110:
      return "110 - read:AB, write:B, increment:B, decrement:AB"
    if bits == 0b001:
      return "001 - read:AB, decrement:AB"
    if bits == 0b011:
      return "011 - read:B, write:B"
    if bits == 0b101:
      return "101 - read:B"
    if bits == 0b111:
      return "111 - no access"
    unreachable

  static trailer_access_bits_to_string bits/int -> string:
    if bits == 0b000:
      return "000 - Key A: Aw, Bits: Ar, Key B: Arw"
    if bits == 0b010:
      return "010 - Bits: Ar, Key B: Ar"
    if bits == 0b100:
      return "100 - Key A: Bw, Bits: Ar Br,  Key B: Bw"
    if bits == 0b110:
      return "110 - Bits: Ar Br"
    if bits == 0b001:
      return "001 - Key A: Aw, Bits: Arw, Key B: Arw"
    if bits == 0b011:
      return "011 - Key A: Bw, Bits: Ar Brw, Key B: Bw"
    if bits == 0b101:
      return "101 - Bits: Ar Brw"
    if bits == 0b111:
      return "111 - Bits: Ar Br"
    unreachable

  /**
  Dumps the content of the card to stdout.

  If there is an authentication error automatically reconnects. This might wake up other
    cards that are in the field.
  */
  write_to_stdout --keys/List=(List sectors_count: DEFAULT_KEY) --print_last_first/bool=true:
    check_keys_ keys
    result := ByteArray total_block_count * 16
    sector_counter := 0
    key/ByteArray? := null
    block := 0
    while block < total_block_count:
      if is_first_block_in_sector block:
        if block != 0: print
        print "Sector $sector_counter:"
        // Set the key so we can update the trailer block later.
        key = keys[sector_counter]
        authenticated := authenticate --block=block key
        if not authenticated:
          print "  encrypted"
          reset_communication_
          // Skip over the remaining blocks in this sector.
          block += sector_size_in_blocks sector_counter
          sector_counter++
          continue

      blocks := []
      sector_size := sector_size_in_blocks sector_counter
      for j := 0; j < sector_size; j++:
        block_bytes := read --block=block
        if is_trailer_block block: block_bytes.replace 0 key
        blocks.add block_bytes
        block++

      access_bits := access_bits_from_trailer blocks.last
      for i := 0; i < blocks.size; i++:
        block_bytes := blocks[i]
        block_str := ""
        block_bytes.do: block_str += "$(%02x it)"
        access_bits_for_block := ?
        if sector_size == 4:
          access_bits_for_block = access_bits[i]
        else
          if i < 5: access_bits_for_block = access_bits[0]
          else if i < 10: access_bits_for_block = access_bits[1]
          else if i < 15: access_bits_for_block = access_bits[2]
          else: access_bits_for_block = access_bits[3]

        legend := ?
        if i != blocks.size - 1: legend = data_access_bits_to_string access_bits_for_block
        else: legend = trailer_access_bits_to_string access_bits_for_block

        print "  $block_str ($legend)"

      sector_counter++

  throw_mifare_error_ response/ByteArray:

    if response.size != 1: throw "Invalid response size"
    if response[0] == 0x00: throw "Invalid operation"
    if response[0] == 0x01: throw "Parity or CRC error"

  check_manufacturer_data_ bytes/ByteArray:
    // We assume that the UID must be of the same size as the current UID.
    // Magic cards generally don't allow to switch UID size.
    new_uid_bytes := bytes[..uid.size]
    bcc := 0
    new_uid_bytes.do: bcc ^= it
    if bcc != bytes[uid.size]: throw (MifareException.from_code MifareException.INVALID_UID_BCC)

  check_trailer_data_ byte/ByteArray --allow_lockout/bool:

  reset_communication_:
    transceiver_.stop_crypto_
    halt_
    transceiver_.wake_up_cards_
    transceiver_.select_ uid


class MifareException:
  static INVALID_OPERATION_VALID_BUFFER ::= 0x00
  static PARITY_OR_CRC_ERROR_VALID_BUFFER ::= 0x01
  static INVALID_OPERATION_INVALID_BUFFER ::= 0x04
  static PARITY_OR_CRC_ERROR_INVALID_BUFFER ::= 0x05

  /**
  The card did not return an ACK, but the response did not match any known error code
    or format.
  */
  static INVALID_ERROR_RESPONSE ::= -1
  /**
  When writing the manufacturer block, the BCC (block check character) was found to be
    invalid.
  A BCC is a checksum over the UID bytes, and an invalid BCC can brick magic cards.
  */
  static INVALID_UID_BCC ::= -2
  /**
  The access bits of a trailer block are duplicated in such a way that each bit has
    a corresponding inverted bit. This error is used when that's not the case.
  */
  static INVALID_ACCESS_BITS ::= -3

  /**
  The Mifare authentication failed.
  */
  static AUTHENTICATION_FAILED ::= -4

  /** The received data, if any. */
  response/ByteArray?

  /**
  The code of the error.

  Codes $INVALID_OPERATION_VALID_BUFFER, $PARITY_OR_CRC_ERROR_VALID_BUFFER, $INVALID_OPERATION_INVALID_BUFFER and
    $PARITY_OR_CRC_ERROR_INVALID_BUFFER are responses from the Mifare card. Other codes are defined by this library.
  */
  code/int

  constructor.from_response .response/ByteArray:
    if response.size != 1: code = INVALID_ERROR_RESPONSE
    if response[0] != INVALID_OPERATION_VALID_BUFFER and response[0] != PARITY_OR_CRC_ERROR_VALID_BUFFER and
        response[0] != INVALID_OPERATION_INVALID_BUFFER and response[0] != PARITY_OR_CRC_ERROR_INVALID_BUFFER:
      code = INVALID_ERROR_RESPONSE
    else:
      code = response[0]

  constructor.from_code .code:
    response = null

  stringify -> string:
    if code == INVALID_OPERATION_VALID_BUFFER: return "Invalid operation (valid buffer)"
    if code == PARITY_OR_CRC_ERROR_VALID_BUFFER: return "Parity or CRC error (valid buffer)"
    if code == INVALID_OPERATION_INVALID_BUFFER: return "Invalid operation (invalid buffer)"
    if code == PARITY_OR_CRC_ERROR_INVALID_BUFFER: return "Parity or CRC error (invalid buffer)"
    if code == INVALID_ERROR_RESPONSE: return "Invalid response: $response"
    if code == INVALID_UID_BCC: return "Invalid UID BCC"
    if code == INVALID_ACCESS_BITS: return "Invalid access bits"
    if code == AUTHENTICATION_FAILED: return "Authentication failed"
    return "Unknown error code: $code"
