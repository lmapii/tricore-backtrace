# -*- coding: utf-8 -*-

import os
from typing import Tuple

import logging

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.lineprogram import LineProgram
from elftools.dwarf.descriptions import describe_form_class

from .common import as_string


class ElfInfoError(Exception):  # pylint: disable=missing-class-docstring
    pass


class ElfData:  # pylint: disable=too-few-public-methods
    """
    Container class for ELF information.
    """

    def __init__(self, path_: str) -> None:
        super().__init__()

        with open(path_, "rb") as file_:
            elf_file = ELFFile(file_)

            self.dwarf_info = elf_file.get_dwarf_info()
            self._symtab_ = elf_file.get_section_by_name(".symtab")

            if not elf_file.has_dwarf_info():
                raise ElfInfoError("No DWARF information found in .elf file")
            if self._symtab_ is None:
                raise ElfInfoError("No symbol table found in .elf file")

            self.aranges = self.dwarf_info.get_aranges()

            # fetch all symbols that have a name - in contrast to iterating over all CUs and DIEs
            # this operation is fairly fast even for large ELF files. sort the symbols by address
            # such that we can pinpoint the matching symbol for each return address as a location
            # between two symbols.
            self.symbols = list(
                filter(
                    lambda x: x.name,
                    sorted(
                        self._symtab_.iter_symbols(),
                        key=lambda y: y.entry["st_value"],
                        reverse=False,
                    ),
                )
            )


def match_subprogram(entry: DIE, address: int) -> DIE | None:
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


def match_line(line_prog: LineProgram, address: int) -> Tuple[str, int] | None:
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
            return as_string(filename), line
        if entry.state.end_sequence:
            prevstate = None
        else:
            prevstate = entry.state
    return None


def get_file_detail_for_cu(die: DIE) -> str | None:
    """
    Provides the composed file path for the compilation unit, if available.
    """
    try:
        # if die.cu.has_top_DIE():
        die_file_path = as_string(die.cu.get_top_DIE().attributes["DW_AT_name"].value)
        die_comp_path = as_string(
            die.cu.get_top_DIE().attributes["DW_AT_comp_dir"].value
        )
    except:  # pylint: disable=bare-except
        return None

    path_ = os.path.join(die_comp_path, die_file_path)
    # DW_AT_comp_dir sometimes double-escapes backslashes ...
    return os.path.normpath(path_.replace("\\\\", "/").replace("\\", "/"))
