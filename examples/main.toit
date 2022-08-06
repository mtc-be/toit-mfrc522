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

main:
  bus := spi.Bus
      --clock = gpio.Pin SPI_CLK
      --mosi = gpio.Pin SPI_MOSI
      --miso = gpio.Pin SPI_MISO

  device := bus.device --cs=(gpio.Pin SPI_SS) --frequency=1_000_000

  reader := mfrc522.Mfrc522 device

  // reader.self_test

  reader.on

  iteration := 0
  while true:
    iteration++
    catch --trace:
      // print "reading"
      while reader.is_new_card_present:
        data := reader.select
        print "--------------- $iteration $data"

    reader.antenna_off
    sleep --ms=2_000
    reader.antenna_on
    sleep --ms=1_000
