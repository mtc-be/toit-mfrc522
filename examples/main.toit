// Copyright (C) 2022 Toitware ApS.
// Use of this source code is governed by a Zero-Clause BSD license that can
// be found in the EXAMPLES_LICENSE file.

import mfrc522
import spi
import gpio

SPI_MOSI ::= 23
SPI_MISO ::= 19
SPI_CLK ::= 18
SPI_SS ::= 5

/*
rkf rejsekort denmark
sector 0-7:   a: fc00018778f7  b: 00000ffe2488
sector 8-12:  a: 0297927c0f77  b: ee0042f88840
sector 13-38: a: 722bfcc5375f  b: f1d83f964314
sector 39:    a: fc00018778f7  b: 00000ffe2488

Idraetscentre:
sector 4-14: a: 3E65E4FB65B3
*/

main:
  bus := spi.Bus
      --clock = gpio.Pin SPI_CLK
      --mosi = gpio.Pin SPI_MOSI
      --miso = gpio.Pin SPI_MISO

  device := bus.device --cs=(gpio.Pin SPI_SS) --frequency=1_000_000

  reader := mfrc522.Mfrc522 device

  reader.self_test

  reader.on

  iteration := 0
  while true:
    iteration++

    catch --trace:
      found_piccs := []
      reader.do --new:
        print "--------------- $iteration $it"
        found_piccs.add it

      found_piccs.do:
        reader.with_picc it.uid:
          if it is mfrc522.MifareCard:
            mifare := it as mfrc522.MifareCard

            // TODO(florian): figure out how we can authenticate
            // again after we used a bad password.
            for i := 63; i >= 0; i--:
              is_first_block_in_sector := (i + 1) % 4 == 0
              if is_first_block_in_sector:
                mifare.authenticate --block=i
              if not mifare.is_authenticated:
                print "Block $i encrypted"
                mifare.transceiver_.stop_crypto_
                continue
              block_data := mifare.read --block=i
              is_trailer_block := (i + 1) % 4 == 0
              trailer_suffix := ""
              if is_trailer_block:
                c1 := block_data[7] >> 4
                c2 := block_data[8] & 0xf
                c3 := block_data[8] >> 4
                c1_ := block_data[6] & 0xf
                c2_ := block_data[6] >> 4
                c3_ := block_data[7] & 0xf

                // cX_ should always be the inverted version of cX.
                if c1_ != 0xf - c1 or c2_ != 0xf - c2 or c3_ != 0xf - c3:
                  trailer_suffix = "(invalid checksum)"
                else:
                  b0 := (c1 & 0b0001) << 2 | (c2 & 0b0001) << 1 | (c3 & 0b0001) << 0
                  b1 := (c1 & 0b0010) << 1 | (c2 & 0b0010) << 0 | (c3 & 0b0010) >> 1
                  b2 := (c1 & 0b0100) << 0 | (c2 & 0b0100) >> 1 | (c3 & 0b0100) >> 2
                  b3 := (c1 & 0b1000) >> 1 | (c2 & 0b1000) >> 2 | (c3 & 0b1000) >> 3
                  /*
                  Access bits.
                  For the trailer:
                            Key A, Access bits, Key B
                    0b000: Aw   ,  Ar        , Arw      # Key B is readable.
                    0b010:      ,  Ar        , Ar       # Key B is readable.
                    0b100:    Bw,  Ar  Br    ,     Bw
                    0b110:      ,  Ar  Br    ,
                    0b001: Aw   ,  Arw       , Arw      # Transport configuration. Key B is readable.
                    0b011:    Bw,  Ar  Brw   ,     Bw
                    0b101:      ,  Ar  Brw   ,
                    0b111:      ,  Ar  Br    ,

                  For the data blocks:
                            read write increment decrement/transfer/restore
                    0b000:   AB   AB      AB       AB    # Transport configuration
                    0b010:   AB   --      --       --    # read/write block
                    0b100:   AB    B      --       --    # read/write block
                    0b110:   AB    B       B       AB    # value block
                    0b001:   AB   --      --       AB    # value block
                    0b011:    B    B      --       --    # read/write block
                    0b101:    B   --      --       --    # read/write block
                    0b111:   --   --      --       --    # read/write block
                  */
                  trailer_suffix = " (access bits: $(%x b0) $(%x b1) $(%x b2) $(%x b3))"
              print "$block_data$trailer_suffix"

            if mifare.uid == #[0x13, 0x59, 0x70, 0x15]:
              print "writing to block 2 of sector 1"
              mifare.authenticate --block=5
              print "old: $(mifare.read --block=5)"
              mifare.write --block=5 #[ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f ]

    reader.antenna_off
    sleep --ms=2_000
    reader.antenna_on
