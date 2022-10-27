# -*- coding: utf-8 -*-

import os
import logging

from array import array
from typing import Any

import zlib

from intelhex import IntelHex

from .common import Err


def __calc_crc__(data: array | bytes) -> int:
    return 0xFFFFFFFF - zlib.crc32(data, 0)


def load(path_: str, offset=0) -> Any | bytes:
    """
    Load message frame from a memory dump in the format of a `.hex` or `.bin` file. For the
    `.hex` file the provided offset is applied. Returns an error message in case of failure.
    In case of success the function returns `None` and simply updates its fields.

    The paramter `offset` is ignored for any file type but `.hex` files.
    """
    ext = str.lower(os.path.splitext(path_)[1])[1:]
    ext = ext if ext == "hex" else "bin"

    ihex_data = IntelHex()
    ihex_data.loadfile(path_, format=ext)

    if ext != "hex":
        offset = 0

    data_length = 0
    with open(path_, "rb") as raw_file:  # pylint: disable=unspecified-encoding
        data_length = len(raw_file.read())

    if data_length < 8:
        raise Err(
            f"File length {data_length} underflow (min. length 8):::"
            "Are you sure that this is a valid .bin/.hex file?"
        )

    crc_ = int("".join([f"{ihex_data[offset + 0 + i]:02X}" for i in range(4)]), 16)
    len_ = int("".join([f"{ihex_data[offset + 4 + i]:02X}" for i in range(4)]), 16)

    # plausibility check for length
    if len_ > data_length:
        raise Err(f"Encoded length {len_} is larger than file size {data_length}")
    raw_ = ihex_data[offset + 8 : offset + 8 + len_].tobinstr()

    crc_calc = __calc_crc__(raw_)
    logging.debug("Message length is %d bytes (file size is %d bytes)", len_, len(raw_))
    logging.debug(
        "Message checksum 0x%08X (calculated checksum 0x%08X)", crc_, crc_calc
    )

    if crc_calc != crc_:
        raise Err(
            f"CRC mismatch:::0x{crc_:08X} does not match calculated CRC 0x{crc_calc:08X}",
        )
    return raw_
