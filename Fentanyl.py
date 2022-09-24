"""
Fentanyl.py

Main Fentanyl class.

"""

import idaapi
import idautils
import idc
from Util import *

__all__ = ['Fentanyl']

# Generate a mapping between each set of jumps
_JUMPS = [
    ('jnb', 'jb'), ('jna', 'ja'),
    ('jnl', 'jl'), ('jng', 'jg'),
    ('jnbe', 'jbe'), ('jnae', 'jae'),
    ('jnle', 'jle'), ('jnge', 'jge'),
    ('jns', 'js'),
    ('jnp', 'jp'),
    ('jnz', 'jz'),
    ('jnc', 'jc'),
    ('jne', 'je'),
    ('jno', 'jo'),
]
# Generate the opposite mapping as well
_JUMPS = dict(_JUMPS + [i[::-1] for i in _JUMPS])


class Fentanyl(object):
    """ Manages assembling into an IDB and keeping track of undo/redo stacks """
    JUMPS = _JUMPS
    PART_RE = re.compile(r'(\W+)')

    def __init__(self):
        """ Initialize our data """
        self.undo_buffer = []
        self.redo_buffer = []

    def _pushundo(self, entries):
        """ Insert one state into the undo stack """
        self.undo_buffer.append(entries)

    def _pushredo(self, entries):
        """ Insert one state into the redo stack """
        self.redo_buffer.append(entries)

    def _popundo(self):
        """ Pop one state into the undo stack """
        return self.undo_buffer.pop() if self.undo_buffer else None

    def _popredo(self):
        """ Pop one state into the redo stack """
        return self.redo_buffer.pop() if self.redo_buffer else None

    def _statedo(self, n, rd_f, wr_f):
        entries = None
        for i in range(n):
            entries = rd_f()
            if not entries: return
            buf = []
            for data in entries:
                buf.append(
                    (data[0], read_data(data[0], len(data[1])))
                )
                write_data(data[0], data[1])
            # Apply to the other stack in reverse order
            wr_f(buf[::-1])

        # Jump to the first entry if an operation was performed
        if entries:
            idaapi.jumpto(entries[0][0])

        return entries

    def _getregvars(self, ea):
        """ Return all the regvar mappings as a dict """
        func = idaapi.get_func(ea)
        regvars = {}

        # XXX: Broken in idapython
        # mapping = {rv.user: rv.canon for rv in func.regvars}

        # Check if each regvar exists and add it to the dict
        regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
        for r in regs:
            rv = idaapi.find_regvar(func, ea, r)
            if not rv: continue
            regvars[rv.user] = rv.canon

        return regvars

    def _fixup(self, parts, regvars):
        """ Fixup an instruction """
        nparts = []
        for i in parts:
            # Fixup regvars
            if i in regvars:
                nparts.append(regvars[i])
            # Fixup .got.plt entries (IDA turns '.' into '_')
            elif i and i[0] == '_':
                nparts.append(i.replace('_', '.', 1))
            # Default case
            else:
                nparts.append(i)

        return ''.join(nparts)

    def assemble(self, ea, asm, save_state=True, opt_fix=True, opt_nop=True):
        """ Assemble into memory """
        # Fixup the assemble
        if opt_fix:
            regvars = self._getregvars(ea)
            parts_arr = [self.PART_RE.split(i) for i in asm]
            asm = []
            for parts in parts_arr:
                asm.append(self._fixup(parts, regvars))

        # Assemble to a string
        success, data = idautils.Assemble(ea, asm)
        if not success:
            return success, data
        print(data)
        blob = ''.join([str(d) for d in data])

        if len(blob) > instr_size(ea):
            if idaapi.askyn_c(0,
                              "The assembled instruction is bigger than the current instruction. This will clobber following instructions. Continue?") != 1:
                return

        # Pad the blob with nops
        if opt_nop:
            nsuccess, nop_instr = idautils.Assemble(ea, 'nop')
            if not nsuccess:
                return nsuccess, nop_instr

            i = ea
            while i < ea + len(blob):
                i += instr_size(i)
            # Only pad if we trashed the next instruction
            sz_diff = (i - (ea + len(blob))) / len(nop_instr)
            blob += nop_instr * sz_diff

        # Write out the data
        old = read_data(ea, len(blob))
        if save_state:
            self._pushundo(
                [(ea, old)]
            )
            self.redo_buffer = []
        write_data(ea, blob)
        return success, old

    def nopout(self, ea, sz):
        """ NOP out a section of memory """
        nsuccess, nop_instr = idautils.Assemble(ea, 'nop')
        if not nsuccess:
            return nsuccess, nop_instr
        return self.assemble(ea, ['nop'] * (sz / len(nop_instr)))

    def nopxrefs(self, ea):
        """ Nop out all xrefs to a function """
        nsuccess, nop_instr = idautils.Assemble(ea, 'nop')
        if not nsuccess:
            return nsuccess, nop_instr

        xrefs = idautils.XrefsTo(ea)
        buf = []
        for i in xrefs:
            success, old = self.assemble(i.frm, ['nop'], False)
            if not success: continue

            buf.append((ea, old))
        self._pushundo(buf)
        self.redo_buffer = []

    def togglejump(self, ea):
        """ Toggle jump condition """
        inst = idautils.DecodeInstruction(ea)
        mnem = inst.get_canon_mnem()
        if mnem not in self.JUMPS: return False
        return self.assemble(ea, [idc.GetDisasm(ea).replace(mnem, self.JUMPS[mnem])])

    def uncondjump(self, ea):
        """ Make a jump unconditional """
        inst = idautils.DecodeInstruction(ea)
        mnem = inst.get_canon_mnem()
        if mnem not in self.JUMPS: return False
        return self.assemble(ea, [idc.GetDisasm(ea).replace(mnem, 'jmp')])

    def undo(self, n=1):
        """ Undo modifications """
        return self._statedo(n, self._popundo, self._pushredo);

    def redo(self, n=1):
        """ Redo modifications """
        return self._statedo(n, self._popredo, self._pushundo);

    def clear(self):
        """ Clear our state """
        self.redo_buffer = []
        self.undo_buffer = []

# print(DecodeInstruction)
