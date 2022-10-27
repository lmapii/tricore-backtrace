# pylint: disable=missing-docstring

import sys
import logging


class Err(Exception):  # pylint: disable=missing-class-docstring
    pass


def as_string(data):
    """
    Helper function to enforce UTF-8 encoding on bytes and strings.
    """
    if isinstance(data, bytes):
        return data.decode("utf-8")
    if not isinstance(data, str):
        raise ValueError(f"unexpected type {type(data)}, need str")
    return data


def abort_with_err(exc):
    """
    Helper function to exit with an error code in case `exc` contains an error message or exception.
    """
    if exc is None:
        return
    error_str = str(exc).split(":::")
    for lvl, str_ in enumerate(error_str):
        indent = "    " * (lvl + 1)
        error_str[lvl] = (
            indent + "|_ " + str_.strip().replace("\n", "\n" + indent + "   ")
        )
    error_str = "\n".join(error_str)
    logging.error("execution failed: \n%s", error_str)
    sys.exit(1)
