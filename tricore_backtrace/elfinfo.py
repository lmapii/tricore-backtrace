# -*- coding: utf-8 -*-

import os

import logging
from typing import List, Tuple

from elftools.dwarf import constants as elfconst
from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.lineprogram import LineProgram
from elftools.dwarf.descriptions import describe_form_class

from .common import as_string, Err


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
                raise Err("No DWARF information found in .elf file")
            if self._symtab_ is None:
                raise Err("No symbol table found in .elf file")

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


def match_address(entry: DIE, address: int) -> bool:
    """
    Adapted from `pyelftools/examples/dwarf_decode_address.py::decode_file_line`.
    Tries to match the given debug info entry for the given address: If it is a subprogram, it
    checks if the given address is within its range. This function does not support subprograms that
    have split address ranges.
    """
    try:
        name_ = entry.attributes["DW_AT_name"].value
    except:  # pylint: disable=bare-except
        name_ = f"{entry.tag} at {entry.offset}"

    try:
        lo_pc_val = entry.attributes["DW_AT_low_pc"].value
        hi_pc_attr = entry.attributes["DW_AT_high_pc"]
    except:  # pylint: disable=bare-except
        return False

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
        return False

    if lo_pc_val <= address <= hi_pc:
        return True
    return False


def match_subprogram(entry: DIE, address: int) -> DIE | None:
    if entry.tag != "DW_TAG_subprogram":
        return None

    if match_address(entry, address):
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


def get_file_detail(die: DIE) -> str | None:
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


# TODO: don't log, provide error with list
def _traverse_type(die: DIE) -> list[str]:
    """
    Experimental, recursive function for traversing the debugging information to reconstruct
    a DW_AT_type value.
    """
    tag = as_string(die.tag)

    # ignored qualifiers that are not important for the type re-construction, i.e., the
    # following qualifiers will simply not be displayed in the reconstruction.
    skip = [
        "DW_TAG_packed_type",
        "DW_TAG_restrict_type",
        "DW_TAG_shared_type",
    ]
    if tag in skip:
        return _traverse_type(die.get_DIE_from_attribute("DW_AT_type"))

    # the following qualifiers are important and must therefore be annotated to the tag. they
    modifiers = {
        "DW_TAG_volatile_type": "volatile",
        "DW_TAG_const_type": "const",
        "DW_TAG_pointer_type": "*",
        "DW_TAG_union_type": "union",
        "DW_TAG_structure_type": "struct",
        "DW_TAG_array_type": "[]",
        "DW_TAG_reference_type": "&",
        "DW_TAG_rvalue_reference_type": "&&",
    }
    if tag in modifiers:
        return _traverse_type(die.get_DIE_from_attribute("DW_AT_type")) + [
            modifiers[die.tag]
        ]

    # for re-constructing a prototype, (base) types and classes are sufficient, i.e., it is not
    # necessary to further resolve the type to its base-type. this could be done in the future
    # to determine the actual argument size and to assign function parameter values from the
    # lower context or stack to the call.
    types_ = [
        "DW_TAG_base_type",
        "DW_TAG_typedef",
        "DW_TAG_class_type",
    ]
    if tag in types_:
        return [as_string(die.attributes["DW_AT_name"].value)]

    logging.warning("Unknown DWARF tag %s, aborting traverse with <unknown>", tag)
    return ["<unknown>"]


# class FunProto:  # pylint: disable=too-few-public-methods
#     """
#     Function prototype.
#     """

#     def __init__(self) -> None:
#         self.type_ = None
#         self.name_ = None
#         self.args = []


def fun_prototype(die: DIE) -> str:
    """
    This function attempts to reconstruct a function prototype using DWARF information. It is higly
    experimental and may not support all variants and/or options.
    """
    if die.tag != "DW_TAG_subprogram":
        raise Err(f"Unsupported tag '{die.tag}', expected 'DW_TAG_subprogram'")

    fun_mod = ""
    if "DW_AT_inline" in die.attributes:
        # DW_INL_not_inlined
        #   Not declared inline nor inlined by the compiler (equivalent to the absence of the
        #   containing DW_AT_inline attribute)
        # DW_INL_inlined
        #   Not declared inline but inlined by the compiler
        # DW_INL_declared_not_inlined
        #   Declared inline but not inlined by the compiler
        # DW_INL_declared_inlined
        #   Declared inline and inlined by the compiler
        inlined = [
            elfconst.DW_INL_declared_not_inlined,
            elfconst.DW_INL_declared_inlined,
        ]
        if die.attributes["DW_AT_inline"].value in inlined:
            fun_mod = "inline "

    fun_name = "<unnamed>"
    if "DW_AT_name" in die.attributes:
        fun_name = as_string(die.attributes["DW_AT_name"].value)

    fun_ret = "void"
    if "DW_AT_type" in die.attributes:
        fun_ret = " ".join(_traverse_type(die.get_DIE_from_attribute("DW_AT_type")))
    fun_ret = fun_mod + fun_ret

    fun_args = []
    for child in die.iter_children():
        if child.tag == "DW_TAG_formal_parameter":
            arg_name = "<unnamed>"
            arg_type = "<unknown>"
            if "DW_AT_name" in child.attributes:
                arg_name = as_string(child.attributes["DW_AT_name"].value)
            if "DW_AT_type" in child.attributes:
                arg_type = " ".join(
                    _traverse_type(child.get_DIE_from_attribute("DW_AT_type"))
                )
            fun_args.append(f"{arg_type} {arg_name}")

    return " ".join([fun_ret, fun_name, "(", ", ".join(fun_args), ")"])


def expand_inline(die: DIE, addr: int) -> List:
    """
    Tries to find inlined functions and recurisvely expands them according to the given address.
    Returns an empty list if no inline functions could be found.
    """
    if die is None:
        return []

    for child in die.iter_children():
        # check if there are inlined routines
        if child.tag != "DW_TAG_inlined_subroutine":
            continue

        # check if there is a known line for the inlined routine. if not, there's no point
        # in expanding this subroutine since we can't provide any additional information.
        if "DW_AT_call_line" not in child.attributes:
            continue

        # check if we can find a subprogram / debug information for the inlined function
        if not match_address(child, addr):
            continue

        prog = child.get_DIE_from_attribute("DW_AT_abstract_origin")
        call_line = child.attributes["DW_AT_call_line"].value
        line_prog = die.dwarfinfo.line_program_for_CU(die.cu)

        # try to find the exact location of the inlined function to further decompose it
        for entry in line_prog.get_entries():
            if entry.state is None:
                continue
            if int(entry.state.line) == int(call_line):
                filename = line_prog["file_entry"][entry.state.file - 1].name
                return [
                    {
                        "line": child.attributes["DW_AT_call_line"].value,
                        "file": as_string(filename),
                        "addr": entry.state.address,
                        "prog": prog,
                    }
                ] + expand_inline(child, addr)

        # if we didn't find an exact match, assume the inlined function is placed within the
        # same compilation unit. notice that the call_line and address have already been matched
        try:
            filename = as_string(die.cu.get_top_DIE().attributes["DW_AT_name"].value)
            filename = os.path.basename(filename)
        except:  # pylint: disable=bare-except
            filename = "??"

        return [
            {
                "line": call_line,
                "file": filename,
                "addr": addr,
                "prog": prog,
            }
        ] + expand_inline(child, addr)

    return []
