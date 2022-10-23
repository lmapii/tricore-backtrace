# -*- coding: utf-8 -*-
"""
Reconstruct backtrace from core dump.
"""

import os
import sys

import argparse
import logging
import json

import coloredlogs

import elftools
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

# from ._version import version

__V_LEVELS__ = {
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "critical": logging.CRITICAL,
}


def _match_subprogram(entry, address):
    """
    Adapted from `pyelftools/examples/dwarf_decode_address.py::decode_file_line`.
    Tries to match the given debug info entry for the given address: If it is a subprogram, it
    checks if the given address is within its range. This function does not support subprograms that
    have split address ranges.
    """
    if entry.tag != "DW_TAG_subprogram":
        return None

    try:
        name_ = entry.attributes["DW_AT_name"].value
        lo_pc_val = entry.attributes["DW_AT_low_pc"].value
        hi_pc_attr = entry.attributes["DW_AT_high_pc"]
    except:  # pylint: disable=bare-except
        return None

    # DWARF v4 in section 2.17 describes how to interpret the DW_AT_high_pc attribute based on the
    # class of its form. For class 'address' it's taken as an absolute address (similarly to
    # DW_AT_low_pc); for class 'constant', it's an offset from DW_AT_low_pc.
    hi_pc_class = describe_form_class(hi_pc_attr.form)

    if hi_pc_class == "address":
        hi_pc = hi_pc_attr.value
    elif hi_pc_class == "constant":
        hi_pc = lo_pc_val + hi_pc_attr.value
    else:
        logging.warning(
            "Invalid class DW_AT_high_pc encountered for subprogram %s: "
            "Expected one of 'address', 'constant', got %s",
            name_,
            hi_pc_class,
        )
        return None

    # logging.info("name %s", name_)
    if lo_pc_val <= address < hi_pc:
        return entry
    return None


def _match_line(line_prog, address):
    """
    Adapted from `pyelftools/examples/dwarf_decode_address.py::decode_file_line`.
    Tries to match the given absolute address against the line program to find the matching
    file-line for an instruction. Notice that a single line of code consists of multiple
    instructions and therefore a range-match is necessary.

    This function implements a lazy match and may not work properly for code containing jumps
    and/or inline functions.
    """
    prevstate = None
    for entry in line_prog.get_entries():
        # We're interested in those entries where a new state is assigned
        if entry.state is None:
            continue
        # look for a range of addresses in two consecutive states that contain the required address
        if prevstate and prevstate.address <= address < entry.state.address:
            filename = line_prog["file_entry"][prevstate.file - 1].name
            line = prevstate.line
            return f"{__as_string__(filename)}:{line}"
        if entry.state.end_sequence:
            # For the state with `end_sequence`, `address` means the address
            # of the first byte after the target machine instruction
            # sequence and other information is meaningless. We clear
            # prevstate so that it's not used in the next iteration. Address
            # info is used in the above comparison to see if we need to use
            # the line information for the prevstate.
            prevstate = None
        else:
            prevstate = entry.state
    return None


# def _assemble_fun(fun_die: elftools.dwarf.die.DIE):
#     fun_name = __as_string__(fun_die.attributes["DW_AT_name"].value)
#     params = []
#     for child in fun_die.iter_children():
#         if child.tag != "DW_TAG_formal_parameter":
#             continue
#         params.append(__as_string__(child.attributes["DW_AT_name"].value))
#     return f"{fun_name}({', '.join(params)})"


def _get_cu_file_detail(die: elftools.dwarf.die.DIE):
    if die.cu.has_top_DIE():
        die_file_path = __as_string__(
            die.cu.get_top_DIE().attributes["DW_AT_name"].value
        )
        die_comp_path = __as_string__(
            die.cu.get_top_DIE().attributes["DW_AT_comp_dir"].value
        )

        path_ = os.path.join(die_comp_path, die_file_path)
        if os.path.isabs(path_):
            path_ = os.path.abspath(path_)

        # DW_AT_comp_dir sometimes double-escapes backslashes ...
        return path_.replace("\\\\", "/").replace("\\", "/")

        # pathlib assumes that the path was created on the same operating system
        # return str(pathlib.Path(die_comp_path, die_file_path).resolve())
    return None


def __as_string__(data):
    """
    Helper function to enforce UTF-8 encoding on bytes and strings.
    """
    if isinstance(data, bytes):
        return data.decode("utf-8")
    if not isinstance(data, str):
        raise ValueError(f"unexpected type {type(data)}, need str")
    return data


def __abort_with_err__(exc):
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

    with open("_tmp/_bld/out/Ttc2385DemoTrap.elf", "rb") as file_:
        elffile = ELFFile(file_)

        dwarf_info = elffile.get_dwarf_info()
        symbol_tab = elffile.get_section_by_name(".symtab")

        if not elffile.has_dwarf_info():
            __abort_with_err__("{file_} has no DWARF info")
        if symbol_tab is None:
            __abort_with_err__("{file_} has no symbol table")

        # fetch all symbols that have a name - in contrast to iterating over all CUs and DIEs
        # this operation is fairly fast even for large ELF files. sort the symbols by address
        # such that we can pinpoint the matching symbol for each return address as a location
        # between two symbols.
        sym_sorted = list(
            filter(
                lambda x: x.name,
                sorted(
                    symbol_tab.iter_symbols(),
                    key=lambda y: y.entry["st_value"],
                    reverse=False,
                ),
            )
        )

        for idx in range(0, sym_sorted.__len__() - 1):
            for csa in csa_list:
                if csa["sym"] is not None:
                    continue
                if (
                    sym_sorted[idx].entry["st_value"]
                    <= int(csa["a11"], 16)
                    < sym_sorted[idx + 1].entry["st_value"]
                ):
                    csa["sym"] = {
                        "name": sym_sorted[idx].name,
                        "loc": f"0x{sym_sorted[idx].entry['st_value']:x}",
                    }

        # this program implements a "primitive" match for a given address and assumes that if its
        # location is between two symbols, it belongs to the leading symbol (as this would be the
        # case for normal function calls). since we already have (or don't have) matching symbols
        # and locations for the
        # instead of iterating through all CUs and their DIEs we can rely on the fa
        # to get
        aranges = dwarf_info.get_aranges()
        for csa in csa_list:
            if csa["fun"] is not None or csa["sym"] is None:
                continue

            # pylint: disable-next=unsubscriptable-object
            cu_idx = aranges.cu_offset_at_addr(int(csa["sym"]["loc"], 16))
            if cu_idx is not None:
                cu_entry = dwarf_info.get_CU_at(cu_idx)
                for dbg_info_entry in cu_entry.iter_DIEs():
                    prog = _match_subprogram(dbg_info_entry, int(csa["a11"], 16))
                    if prog is not None:
                        csa["fun"] = __as_string__(prog.attributes["DW_AT_name"].value)
                        csa["file"]["path"] = _get_cu_file_detail(prog)
                        break

                line_prog = dwarf_info.line_program_for_CU(cu_entry)
                csa["file"]["loc_1"] = _match_line(line_prog, int(csa["a11"], 16))
                csa["file"]["loc_0"] = _match_line(line_prog, int(csa["a11"], 16) - 4)

        logging.info("%s", json.dumps(csa_list, indent=2))

    logging.info("")
    logging.info(":) success")


if __name__ == "__main__":
    PARSER_ = argparse.ArgumentParser(description="tricore backtrace")

    PARSER_.add_argument(
        "-v",
        "--verbosity",
        dest="verbosity",
        default="INFO",
        help="verbosity level, one of %s" % list(__V_LEVELS__.keys()),
    )

    ARGS_ = PARSER_.parse_args()

    if (
        ARGS_.verbosity and not ARGS_.verbosity.lower() in __V_LEVELS__.keys()
    ):  # pylint: disable=consider-iterating-dictionary
        PARSER_.error("\nverbosity has to be one of %s" % list(__V_LEVELS__.keys()))

    coloredlogs.install(
        level=__V_LEVELS__[ARGS_.verbosity.lower()],
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="(%H:%M:%S)",
    )

    logging.info("executing %s ...", os.path.basename(__file__))
    __execute__(ARGS_)
