// Copyright (C) 2022 Toitware ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A driver for the MFRC522 RFID reader.
*/

import serial

class Mfrc522:
  static COMMAND_REGISTER_ ::= 0x01 << 1
  static COM_IRQ_REGISTER_ ::= 0x04 << 1
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

  on_:

    current_command := registers_.read_u8 COMMAND_REGISTER_
    print "command: $(%x current_command)"
    // command := 0x00
    // // Bit 5 (RcvOff) must be set to 0 to turn on the analog part of the receiver.
    // command |= 0b1000

    reset_soft_

    registers_.write_u8 COMMAND_REGISTER_ (current_command | 0b0000_1000)
    print "after command 1000 receive $(%x registers_.read_u8 COMMAND_REGISTER_)"

    old := registers_.read_u8 TX_CONTROL_REGISTER_
    registers_.write_u8 TX_CONTROL_REGISTER_ (old | 0x3)
    print "control $(%x registers_.read_u8 TX_CONTROL_REGISTER_)"

  on:
    reset_soft_
    reset_communication_

    // When communicating with a PICC we need a timeout if something goes wrong.
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

  picc_request_a_:
    old := registers_.read_u8 COLL_REGISTER_
    registers_.write_u8 COLL_REGISTER_ (old & 0x7F)

  /*
  Short frame:

  0x26: REQ
  0x52: WUPA
  0x35: Optional timeslot method. (see Annex C of iso14443-3)
  0x40 to 0x4F: Proprietary.
  0x78 to 0x7F: Proprietary.
  all other values: RFU (reserved for future use)
  */



  /// Needs $is_new_card_present to get a PICC into READY state.
  /// (currently only $is_new_card_present) is implemented.
  select:
    // Section 6.5.3.1
    SELECT_CASCADE1 ::= 0x93  // 4 byte UID.
    SELECT_CASCADE2 ::= 0x95  // 7 byte UID.
    SELECT_CASCADE3 ::= 0x97  // 10 byte UID.

    valid_bytes := 2  // Including the command (SEL) and the number of valid bits.
    valid_bits := 0
    encoded_valid_bits := (valid_bytes << 4) + valid_bits

    // The biggest frame consists of 9 bytes:
    // - 1 byte command.
    // - 1 byte valid bits.
    // - 4 bytes of UID (potentially the first one being a Cascade Tag, indicating that the UID needs
    //          an additional cascade level).
    // - 1 byte of BCC (Block Check Character).
    // - 2 bytes of CRC.
    bytes := ByteArray 9
    command := SELECT_CASCADE1
    bytes[0] = command
    bytes[1] = encoded_valid_bits

    // TODO(florian): clear collision bits.

    // Send all bits.
    registers_.write_u8 BIT_FRAMING_REGISTER_ 0x00

    // Mostly copied from $is_new_card_present.
    // Need to reuse code more properly.
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_IDLE_
    registers_.write_u8 COM_IRQ_REGISTER_ 0x7F
    registers_.write_u8 FIFO_LEVEL_REGISTER_ 0x80
    registers_.write_bytes FIFO_DATA_REGISTER_ bytes[0..2]
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_TRANSCEIVE_
    registers_.write_u8 BIT_FRAMING_REGISTER_ (registers_.read_u8 BIT_FRAMING_REGISTER_) | 0x80

    completed := false
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
        throw "TIMEOUT"
      sleep --ms=3
    print "completed: $completed"
    if not completed: return null

    // TODO(florian): we should check the fifo level.
    result := ByteArray 5: registers_.read_u8 FIFO_DATA_REGISTER_

    return result

  /**
  Returns null if not present.
  Returns the ATQA (Answer to Request) otherwise.

  Leaves one or several PICCs in READY state (from IDLE to READY).
  Still need to do anti-collision or go to ACTIVE state.
  */
  is_new_card_present -> ByteArray?:
    reset_communication_

    // Cancel any existing command.
    registers_.write_u8 COMMAND_REGISTER_ COMMAND_IDLE_

    // Clear all irq bits.
    // The MSB of the register is 0, indicating that all marked bits are cleared.
    registers_.write_u8 COM_IRQ_REGISTER_ 0x7F

    // Flush the FIFO buffer.
    // "Immediately clears the internal FIFO buffer's read and write pointer and ErrorReg register's BufferOvfl bit."
    registers_.write_u8 FIFO_LEVEL_REGISTER_ 0x80

    // ISO 14443-3
    PICC_CMD_REQA ::= 0x26

    registers_.write_u8 FIFO_DATA_REGISTER_ PICC_CMD_REQA

    // Check this.
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
    // The PICC_CMD_REQA should be sent in a "short frame" which has only 7 bits.
    // Iso-14443-3, 6.4.1. "The REQA and WUPA commands [..] are transmitted within a short frame".
    registers_.write_u8 BIT_FRAMING_REGISTER_ 0x07

    registers_.write_u8 COMMAND_REGISTER_ COMMAND_TRANSCEIVE_

    // 10.2 General behavior:
    // """
    // Each command that needs a data bit stream (or data byte stream) as an input
    // immediately processes any data in the FIFO buffer.
    // An exception to this rule is the Transceive command. Using this command, transmission is
    // started with the BitFramingReg register's StartSend bit.
    // """
    // Bit 7: StartSend. Start the transmission of data.
    registers_.write_u8 BIT_FRAMING_REGISTER_ (registers_.read_u8 BIT_FRAMING_REGISTER_) | 0x80

    completed := false
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
        throw "TIMEOUT"
      sleep --ms=3
    if not completed: return null

    // Read the ATQA (Answer to Request) frame.
    // ATQA is a standard frame.
    // 16 bits.
    // 15-12: RFU
    // 11-8: Proprietary coding
    // 7-6: UID size bit frame. Must not be 3 (0b11).
    //     0 = single
    //     1 = double
    //     2 = triple.
    //     3 = RFU
    // 5: RFU
    // 4-0: bit frame anticollision
    result := ByteArray 2: registers_.read_u8 FIFO_DATA_REGISTER_
    return result

  // read -> ByteArray?:
  //   level := registers_.read_u8 FIFO_LEVEL_REGISTER_
  //   if level == 0: return null
  //   return ByteArray level: registers_.read_u8 FIFO_DATA_REGISTER_

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
      print "level: $level"
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

    throw "Self test failed; unknown self-test data"

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
