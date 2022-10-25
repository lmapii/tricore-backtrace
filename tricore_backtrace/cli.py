# -*- coding: utf-8 -*-
"""
Reconstruct backtrace from core dump.
"""

import argparse
import logging
import json  # pylint: disable=unused-import

import coloredlogs


from ._version import version
from .common import abort_with_err
from . import elfinfo
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

    # ASSUMPTION: The first matching CSAs are responsible for the trap and thus backtrace, all
    # other CSAs are function calls and therefore we TODO: need to evaluate CALL=RET-4 to get the
    # actuall call location.
    csa_list = [
        {"a11": "0x800661F4", "fun": None, "file": {}, "sym": None},  # u:0
        {"a11": "0x800661F4", "fun": None, "file": {}, "sym": None},  # h:1
        {"a11": "0x80066568", "fun": None, "file": {}, "sym": None},  # h:2
        {"a11": "0x800AC456", "fun": None, "file": {}, "sym": None},  # h:3
        {"a11": "0x800AC34E", "fun": None, "file": {}, "sym": None},  # h:4
    ]

    path_ = "_tmp/_bld/out/Ttc2385DemoTrap.elf"
    try:
        elf_data = elfinfo.ElfData(path_)
    except elfinfo.ElfInfoError as exc:
        abort_with_err(f"Failed to load data from {path_}:::{exc}")

    btraces = []
    for csa in csa_list:
        btraces.append(Backtrace(csa["a11"]))

    symbols = elf_data.symbols
    for idx in range(0, symbols.__len__() - 1):
        for trace in btraces:
            trace.load_symbol(symbols[idx], symbols[idx + 1])

    for trace in btraces:
        trace.load_debug_info(elf_data)

    # print(btraces)
    logging.info("%s", "\n".join([f"{trace}" for trace in btraces]))

    logging.info("")
    logging.info(":) success")


def main():  # pylint: disable=missing-function-docstring
    parser_ = argparse.ArgumentParser(description=f"tricore backtrace {version}")

    # disassembly with capstone would be possible, but tricore is not supported
    # https://www.capstone-engine.org/lang_python.html
    # https://github.com/TriDis/ditricore/issues/1

    # TODO: support partial path-map
    # TODO: support --experimental prototype reconstruction
    parser_.add_argument(
        "-v",
        "--verbosity",
        dest="verbosity",
        default="INFO",
        help="verbosity level, one of %s" % list(__V_LEVELS__.keys()),
    )

    args_ = parser_.parse_args()

    if (
        args_.verbosity and not args_.verbosity.lower() in __V_LEVELS__
    ):  # pylint: disable=consider-iterating-dictionary
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
