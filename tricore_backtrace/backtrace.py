# pylint: disable=missing-docstring

import json
from typing import List
from typing_extensions import Self

from elftools.elf.sections import Symbol
from elftools.dwarf.die import DIE

from .elfinfo import (
    ElfData,
    expand_inline,
    match_subprogram,
    match_line,
    fun_prototype,
)
from .common import as_string


def __guess_address__(address: str | int) -> int:
    if isinstance(address, str):
        return int(address, 0)  # guess the base
    return address


class Backtrace:
    def __init__(self, address: str | int) -> None:
        self.sym = None
        self.debug_info = None
        self.line_prog = None
        self.addr = __guess_address__(address)
        self.die = None

    def __repr__(self):
        # repr_ = self.__dict__
        repr_ = {
            "addr": f"0x{self.addr:x}",
            "sym": self.sym,
            "debug_info": self.debug_info,
            "line_prog": self.line_prog,
            # "die": f"{self.die}",
        }
        return f"{self.__class__.__name__}: {json.dumps(repr_, indent=2)}"

    def load_symbol(self, sym_a: Symbol, sym_b: Symbol, override=False) -> bool:
        if self.sym is not None and not override:
            return False

        if sym_a.entry["st_value"] <= self.addr < sym_b.entry["st_value"]:
            self.sym = {
                "name": sym_a.name,
                "loc": sym_a.entry["st_value"],
                "loc_str": f"0x{sym_a.entry['st_value']:x}",
            }
            return True
        return False

    def set_debug_info(self, die: DIE):
        self.debug_info = {
            "fun": as_string(die.attributes["DW_AT_name"].value),
            # "loc": get_file_detail(die), wrong for inline
            "proto": fun_prototype(die),
        }
        self.die = die

    def load_debug_info(self, elf_data: ElfData, override=False) -> bool:
        """
        This program implements a "primitive" match for the given return address and assumes that,
        if its location is between two symbols, it belongs to the leading symbol (as this would be
        the case for normal function calls).
        This function only works if a symbol has been loaded before such that address ranges
        can be used instead of iterating through all the CUs and their DIEs.
        """
        if self.sym is None:
            return False

        if self.debug_info is not None and not override:
            return False

        cu_idx = elf_data.aranges.cu_offset_at_addr(self.sym["loc"])
        if cu_idx is not None:
            cu_entry = elf_data.dwarf_info.get_CU_at(cu_idx)
            for dbg_info_entry in cu_entry.iter_DIEs():
                prog = match_subprogram(dbg_info_entry, self.addr)
                if prog is None:
                    continue
                self.set_debug_info(prog)
                break

            if self.debug_info is not None:
                return self._load_line_prog(elf_data)
        return False

    def _load_line_prog(self, elf_data: ElfData, override=False) -> bool:
        if self.sym is None:
            return False

        if self.line_prog is not None and not override:
            return False

        # tricore instruction convention: ra = call + 4. thus, if the instruction was a 'call',
        # then `address` points to the return address and therefore the call address is ra - 4
        addr_ca = self.addr - 4

        line_prog = elf_data.dwarf_info.line_program_for_CU(self.die.cu)
        loc_ra = match_line(line_prog, self.addr)
        loc_ca = match_line(line_prog, addr_ca)

        if loc_ra is None:
            return False

        # TODO: store both, the call estimate and the actual position
        if loc_ca is None or loc_ca[1] > loc_ra[1]:
            self.line_prog = {"file": loc_ra[0], "line": loc_ra[1], "addr": self.addr}
        else:
            self.line_prog = {"file": loc_ca[0], "line": loc_ca[1], "addr": addr_ca}

        self.line_prog["inline"] = None
        return True

    def expand_inline(self) -> List[Self]:
        if self.die is None:
            return [self]

        # print(f"\n#### expand_inline for{self.sym['name']}")
        # print(f"     {self.line_prog}")
        # print(f"     {self.debug_info}")

        inlines = expand_inline(self.die, self.addr)
        if not inlines:
            return [self]

        inlines_bt = []
        for inline in inlines:
            bt_ = Backtrace(inline["addr"])
            bt_.set_debug_info(inline["prog"])
            bt_.line_prog = {
                "file": inline["file"],
                "line": inline["line"],
                "addr": inline["addr"],
                "inline": None,
            }
            inlines_bt.append(bt_)

        # propagate backtraces down the inline callstack
        real_line = self.line_prog
        inlines_bt = [self] + inlines_bt
        for idx in range(0, len(inlines_bt) - 1):
            line_prog = inlines_bt[idx].line_prog
            inlines_bt[idx].line_prog = inlines_bt[idx + 1].line_prog
            inlines_bt[idx].line_prog["inline"] = line_prog

        # the initial address is the actual call address of the last inlined function
        inlines_bt[len(inlines_bt) - 1].line_prog = real_line
        inlines_bt[len(inlines_bt) - 1].line_prog["inline"] = inlines_bt[
            len(inlines_bt) - 2
        ].line_prog
        inlines_bt[0].line_prog["inline"] = None

        return inlines_bt
