"""
Fentanyl.py

IDAPython script to patch binaries. 

IDAPython: https://code.google.com/p/idapython/
Helfpul if you want to run scripts on startup: https://code.google.com/p/idapython/source/browse/trunk/examples/idapythonrc.py

Alt F7 to load scripts

File > Produce file > Create DIF file
Edit > Patch program > Apply patches to input file

Keybindings:
    Shift-N: Convert instruction to nops
    Shift-X: Nop all xrefs to this function
    Shift-J: Invert conditional jump
    Shift-U: Make jump unconditional
    Shift-P: Patch instruction
    Shift-Z: Undo modification (Won't always work. Should still be careful editing.)
    Shift-Y: Redo modification (Won't always work. Should still be careful editing.)

"""

import idaapi
import idautils
import idc
import re

try:
    from PySide import QtGui
    from PySide import QtCore
except ImportError:
    print "PySide unavailable, no GUI"
    pass

#Generate a mapping between each set of jumps
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
#Generate the opposite mapping as well
_JUMPS = dict(_JUMPS + [i[::-1] for i in _JUMPS])


class Fentanyl(object):
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
        for i in range(n):
            entries = rd_f()
            if not entries: return
            buf = []
            for data in entries:
                buf.append(
                    (data[0], self._readdata(data[0], len(data[1])))
                )
                self._writedata(data[0], data[1])
            wr_f(buf)
        return entries

    def _instrsize(self, ea):
        """ Get the size of the instr at ea or 1 """
        instr = DecodeInstruction(ea)
        #If invalid, return 1 to consume this byte
        #XXX: Fixed-width instr sets should add instr size
        return instr.size if instr else 1

    def _getpos(self):
        """ Get the selected area """
        start, end = SelStart(), SelEnd()
        if start == BADADDR:
            start = ScreenEA()
            end = ScreenEA() + self._instrsize(start)
        return start, end

    def _readdata(self, ea, sz):
        """ Read bytes from idb """
        return idaapi.get_many_bytes(ea, sz)

    def _writedata(self, ea, blob, reanalyze=True):
        """ Write bytes to idb """
        if reanalyze: idc.MakeUnknown(ea, len(blob), 0)
        idaapi.patch_many_bytes(ea, blob)
        if reanalyze: idc.MakeCode(ea)

    def _getregvars(self, ea):
        """ Return all the regvar mappings as a dict """
        func = idaapi.get_func(ea)
        regvars = {}

        #XXX: Broken in idapython
        #mapping = {rv.user: rv.canon for rv in func.regvars}

        #Check if each regvar exists and add it to the dict
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
            #Fixup regvars
            if i in regvars: nparts.append(regvars[i])
            #Fixup .got.plt entries (IDA turns '.' into '_')
            elif i and i[0] == '_':
                nparts.append(i.replace('_', '.', 1))
            #Default case
            else: nparts.append(i)

        return ''.join(nparts)

    def assemble(self, ea, asm, save_state=True, opt_fix=True, opt_nop=True):
        """ Assemble into memory """
        #Fixup the assemble
        if opt_fix:
            regvars = self._getregvars(ea)
            parts_arr = [self.PART_RE.split(i) for i in asm]
            asm = []
            for parts in parts_arr:
                asm.append(self._fixup(parts, regvars))

        #Assemble to a string
        success, data = Assemble(ea, asm)
        if not success:
            return success, data
        blob = ''.join(data)

        #Pad the blob with nops
        if opt_nop:
            nsuccess, nop_instr = Assemble(ea, 'nop')
            if not nsuccess:
                return nsuccess, nop_instr

            i = ea
            while i < ea + len(blob):
                i += self._instrsize(i)
            #Only pad if we trashed the next instruction
            sz_diff = (i - (ea + len(blob))) / len(nop_instr)
            blob += nop_instr * sz_diff

        #Write out the data
        old = self._readdata(ea, len(blob))
        if save_state:
            self._pushundo(
                [(ea, old)]
            )
            self.redo_buffer = []
        self._writedata(ea, blob)
        return success, old

    def nopout(self, ea, sz):
        """ NOP out a section of memory """
        nsuccess, nop_instr = Assemble(ea, 'nop')
        if not nsuccess:
            return nsuccess, nop_instr
        return self.assemble(ea, ['nop'] * (sz / len(nop_instr)))

    def nopxrefs(self, ea):
        """ Nop out all xrefs to a function """
        nsuccess, nop_instr = Assemble(ea, 'nop')
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
        inst = DecodeInstruction(ea)
        mnem = inst.get_canon_mnem()
        if mnem not in self.JUMPS: return False
        return self.assemble(ea, [GetDisasm(ea).replace(mnem, self.JUMPS[mnem])])

    def uncondjump(self, ea):
        """ Make a jump unconditional """
        inst = DecodeInstruction(ea)
        mnem = inst.get_canon_mnem()
        if mnem not in self.JUMPS: return False
        return self.assemble(ea, [GetDisasm(ea).replace(mnem, 'jmp')])

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


class AssembleForm(object):
    def __init__(self):
        """ Initialize form elements """
        self.ui_cntls = {
            'inp':idaapi.Form.MultiLineTextControl('', idaapi.textctrl_info_t.TXTF_FIXEDFONT),
            'opt_chk':idaapi.Form.ChkGroupControl(('fixup', 'nopout')),
            'form_cb':idaapi.Form.FormChangeCb(self._form_cb),
        }
        self.ui_form = idaapi.Form("""STARTITEM {id:inp}
BUTTON YES* Assemble
BUTTON NO NONE
BUTTON CANCEL Cancel
Fentanyl Assembler

{form_cb}
<:{inp}>
<Name fixups:{fixup}>
<Fill with NOPs:{nopout}>{opt_chk}>"""
        , self.ui_cntls)
        self.values = None
        self.ui_form.Compile()
        self.ui_form.opt_chk.value = 3

    def __del__(self):
        """ Clean up """
        for i in self.ui_cntls.values(): i.free()
        self.ui_form.Free()

    def _getvalue(self, cntl):
        """ Get value of the control """
        val = self.ui_form.GetControlValue(cntl)

        #Checkboxes get turned into a dict()
        if isinstance(cntl, idaapi.Form.ChkGroupControl):
            names = cntl.children_names
            opts = {}
            for i in range(len(names)):
                opts[names[i]] = val & (2**i)
            val = opts
        else:
            #MultiLineText controls require an extra step to get the text
            if isinstance(cntl, idaapi.Form.MultiLineTextControl):
                val = val.value
        return val

    def _form_cb(self, fid):
        """ Handle callbacks and grab control values """
        #Only continue if Assemble (OK) pressed
        if fid != -2: return

        self.values = dict([
            (k, self._getvalue(v))
            for k, v in self.ui_cntls.items()
            #Exclude the callback, it isn't a control
            if not isinstance(v, idaapi.Form.FormChangeCb)
        ])
        return True

    def process(self):
        """ Execute the form and return values """
        if not self.ui_form.Execute():
            self.values = None
        return self.values


""" Main """

ftl = Fentanyl()
asf = AssembleForm()

#Interfaces to the methods in ftl
def nopout():
    start, end = ftl._getpos()
    ftl.nopout(start, end - start)

def assemble():
    success = False
    while not success:
        v = asf.process()
        if not v or not v['inp'].strip(): return

        start, end = ftl._getpos()
        lines = [i.strip() for i in v['inp'].replace(';', '\n').strip().split('\n')]
        success, data = ftl.assemble(start, lines, v['opt_chk']['fixup'], v['opt_chk']['nopout'])

        if not success:
            print data

def togglejump():
    start, end = ftl._getpos()
    ftl.togglejump(start)

def uncondjump():
    start, end = ftl._getpos()
    ftl.uncondjump(start)

def nopxrefs():
    start, end = ftl._getpos()
    func = idaapi.get_func(start)
    if func:
        ftl.nopxrefs(func.startEA)

def undo():
    if ftl.undo() is None:
        print "Nothing to undo"

def redo():
    if ftl.redo() is None:
        print "Nothing to redo"

def savefile():
    output_file = AskFile(1, "*", "Output File")
    idc.GenerateFile(idaapi.OFILE_DIF, output_file, 0, MaxEA(), 0)
    diff_file = open(output_file, "rb").read()
    orig_file = open(idc.GetInputFilePath(), "rb").read()

    diff_file = diff_file.split("\n")
    for line in diff_file:
        match = re.match("([A-F0-9]+): ([A-F0-9]+) ([A-F0-9]+)", line)
        if match:
            groups = match.groups()
            if orig_file[int(groups[0], 16)] == groups[1].decode('hex'):
                orig_file = orig_file[:int(groups[0], 16)] + groups[2].decode('hex') + orig_file[int(groups[0], 16)+1:]
            else:
                print "Error matching %02x at offset %x..." % (groups[1], groups[0])

    new_file = open(output_file, 'wb')
    new_file.write(orig_file)
    new_file.close()

#Register hotkeys
idaapi.add_hotkey("Shift-N", nopout)
idaapi.add_hotkey("Shift-X", nopxrefs)
idaapi.add_hotkey("Shift-P", assemble)
idaapi.add_hotkey("Shift-J", togglejump)
idaapi.add_hotkey("Shift-U", uncondjump)
idaapi.add_hotkey("Shift-Z", undo)
idaapi.add_hotkey("Shift-Y", redo)
idaapi.add_hotkey("Shift-S", savefile)

#Register menu items
if QtCore:
    qta = QtCore.QCoreApplication.instance()
    #XXX: This filter is too wide...
    menus = [i for i in qta.allWidgets() if isinstance(i, QtGui.QMenu) and i.title() == '' and i.actions() == []]

    entries = [
        ('Nop out', nopout),
        ('Nop out xrefs', nopxrefs),
        ('Assemble', assemble),
        ('Toggle jump', togglejump),
        ('Uncond jump', uncondjump),
    ]
    entries = [
        ('Replace with nops - Shift + N', nopout),
        ('Nops all Xrefs - Shift + X', nopout),
        ('Assemble - Shift + P', assemble),
        ('Toggle jump - Shift + J', togglejump),
        ('Force jump - Shift + U', uncondjump),
    ]

    #Insert each entry into the context menu
    for i in menus:
        i.addSeparator()

        for name, func in entries:
            act = QtGui.QAction(name, qta)
            act.triggered.connect(func)

            i.addAction(act)
