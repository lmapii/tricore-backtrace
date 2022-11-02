# -*- coding: utf-8 -*-
"""
Reconstruct backtrace from core dump.
"""

import os

import argparse
import logging
import json  # pylint: disable=unused-import

import coloredlogs


from ._version import version
from .common import abort_with_err, Err
from . import elfinfo, dump
from .backtrace import Backtrace


__V_LEVELS__ = {
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "critical": logging.CRITICAL,
}


def __execute__(args):  # pylint: disable=unused-argument
    # data = None
    # root_rel = os.path.relpath(os.path.dirname(os.path.abspath(args.json)))

    try:
        elf_data = elfinfo.ElfData(args.elf_path)
    except Err as exc:
        abort_with_err(f"Failed to load data from {args.elf_path}:::{exc}")

    try:
        dump_data = dump.load(args.dump_path)
    except Err as exc:
        abort_with_err(f"Failed to load data from {args.dump_path}:::{exc}")

    dump_ = [dump_data[i : i + 4] for i in range(0, len(dump_data), 4)]
    dump_ = [int.from_bytes(d, byteorder="little") for d in dump_]
    dump_ = [d for d in dump_ if d != 0]
    # dump_ = [
    #     int.from_bytes(struct.pack("<1i", *struct.unpack(">1i", d))) for d in dump_
    # ]
    print(
        json.dumps(
            [f"0x{d:x}" for d in dump_],
            indent=2,
        )
    )

    csa_list = []
    for idx in range(4, len(dump_)):
        a11 = dump_[idx]
        csa_list.append(a11)

    backtrace = []
    for csa in csa_list:
        backtrace.append(Backtrace(csa))

    symbols = elf_data.symbols
    for idx in range(0, symbols.__len__() - 1):
        for trace in backtrace:
            trace.load_symbol(symbols[idx], symbols[idx + 1])

    for trace in backtrace:
        trace.load_debug_info(elf_data)

    ext_backtrace = []
    for trace in backtrace:
        ext = trace.expand_inline()
        ext.reverse()
        ext_backtrace.extend(ext)

    for trace in ext_backtrace:
        if trace.debug_info:
            name_ = trace.debug_info["fun"]
            if trace.debug_info["proto"]:
                name_ = trace.debug_info["proto"]
            loc = "??"
            if trace.line_prog:
                loc = f"{trace.line_prog['file']} at line {trace.line_prog['line']}"
                inline_prog = trace.line_prog["inline"]
                if inline_prog:
                    loc += f" // inlined in {inline_prog['file']} at line {inline_prog['line']}"
            # logging.info("0x%x %s // in %s", trace.addr, name_, loc)
            logging.info("0x%x", trace.addr)
            logging.info("  %s", name_)
            logging.info("    in %s", loc)
        elif trace.sym:
            logging.info("0x%x %s", trace.addr, trace.sym["name"])
        else:
            logging.info("0x%x <unknown>", trace.addr)

    # print(backtrace)
    # logging.info("%s", "\n".join([f"{trace}" for trace in ext_backtrace]))

    logging.info("")
    logging.info(":) success")


def _arg_is_raw_file(parser_, arg):
    if not os.path.isfile(arg):
        parser_.error(f"'{arg}' not found / not a file")
        return None
    return arg


def _arg_is_elf_file(parser_, arg):
    if not os.path.isfile(arg):
        parser_.error(f"'{arg}' not found / not a file")
        return None
    ext = str.lower(os.path.splitext(arg)[1])
    if ext != ".elf":
        parser_.error(f"Unsupported file '{arg}': expected '.elf' file")
        return None
    return arg


# tricore_backtrace --dump ..\..\..\BuildFiles\T32\dump.txt --elf ../../../_bld/out/Ttc2385DemoTrap.elf
def main():  # pylint: disable=missing-function-docstring
    parser_ = argparse.ArgumentParser(description=f"tricore backtrace {version}")

    # disassembly with capstone would be possible, but tricore is not supported
    # https://www.capstone-engine.org/lang_python.html
    # https://github.com/TriDis/ditricore/issues/1

    # TODO: support partial path re/map
    # TODO: support --experimental prototype reconstruction

    parser_.add_argument(
        "-v",
        "--verbosity",
        dest="verbosity",
        default="INFO",
        help="verbosity level, one of %s" % list(__V_LEVELS__.keys()),
    )

    parser_.add_argument(
        "--dump",
        dest="dump_path",
        required=True,
        metavar="dump-path",
        type=lambda x: _arg_is_raw_file(parser_, x),
        help="File to decode (typically a .hex file)",
    )

    parser_.add_argument(
        "--elf",
        dest="elf_path",
        required=True,
        metavar="elf-path",
        type=lambda x: _arg_is_elf_file(parser_, x),
        help="ELF file matching the firmware that created the dump",
    )

    args_ = parser_.parse_args()

    if args_.verbosity and not args_.verbosity.lower() in __V_LEVELS__:
        parser_.error("\nverbosity has to be one of %s" % list(__V_LEVELS__.keys()))

    coloredlogs.install(
        level=__V_LEVELS__[args_.verbosity.lower()],
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="(%H:%M:%S)",
    )

    # logging.info("executing %s ...", os.path.basename(__file__))
    __execute__(args_)


if __name__ == "__main__":
    main()
