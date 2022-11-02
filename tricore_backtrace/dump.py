# -*- coding: utf-8 -*-

import os

from typing import Any
from intelhex import IntelHex

from .common import Err


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

    raw_ = ihex_data[offset : offset + data_length - offset].tobinstr()
    return raw_
