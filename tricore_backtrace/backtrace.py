# pylint: disable=missing-docstring

import json

from elftools.elf.sections import Symbol
from elftools.dwarf.compileunit import CompileUnit

from .elfinfo import ElfData, match_subprogram, get_file_detail_for_cu, match_line
from .common import as_string


class Backtrace:
    def __init__(self, address: str | int) -> None:
        if isinstance(address, str):
            self.addr = int(address, 0)  # guess the base
        else:
            self.addr = address

        self.sym = None
        self.debug_info = None
        self.line_prog = None

    def __repr__(self):
        repr_ = self.__dict__
        repr_["addr"] = f"0x{repr_['addr']:x}"
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
                fun = as_string(prog.attributes["DW_AT_name"].value)
                loc = get_file_detail_for_cu(prog)
                self.debug_info = {"fun": fun, "loc": loc}
                break

            if self.debug_info is not None:
                return self._load_line_prog(cu_entry, elf_data)
        return False

    def _load_line_prog(
        self, compile_unit: CompileUnit, elf_data: ElfData, override=False
    ) -> bool:
        if self.sym is None:
            return False

        if self.line_prog is not None and not override:
            return False

        # tricore instruction convention: ra = call + 4. thus, if the instruction was a 'call',
        # then `address` points to the return address and therefore the call address is ra - 4
        addr_ca = self.addr - 4

        line_prog = elf_data.dwarf_info.line_program_for_CU(compile_unit)
        loc_ra = match_line(line_prog, self.addr)
        loc_ca = match_line(line_prog, addr_ca)

        if loc_ra is None:
            return False

        if loc_ca is None or loc_ca[1] > loc_ra[1]:
            self.line_prog = {"file": loc_ra[0], "line": loc_ra[1], "addr": self.addr}
        else:
            self.line_prog = {"file": loc_ca[0], "line": loc_ca[1], "addr": addr_ca}

        return True
