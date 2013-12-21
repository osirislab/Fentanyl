"""
main.py

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

import os
import idaapi
import idc
import re

import Fentanyl
import AssembleForm
import FtlHooks

try:
    from PySide import QtGui
    from PySide import QtCore
except ImportError:
    print "PySide unavailable, no GUI"
    QtCore = None
    QtGui = None


""" Main """
ftl_path = os.path.dirname(__file__)

ftl = Fentanyl.Fentanyl()
ftl._getpos()
asf = AssembleForm.AssembleForm()
ftlh = FtlHooks.FtlHooks()
ftlh.hook()


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
    if not output_file:
        return
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


#Hotkey definitions
hotkeys = [
    ('Replace with nops', True , ['Ctrl', 'Shift', 'N'], 'nopout.png', nopout),
    ('Nops all Xrefs'   , True , ['Ctrl', 'Shift', 'X'], 'nopxrefs.png', nopxrefs),
    ('Assemble'         , True , ['Ctrl', 'Shift', 'P'], 'assemble.png', assemble),
    ('Toggle jump'      , True , ['Ctrl', 'Shift', 'J'], 'togglejump.png', togglejump),
    ('Force jump'       , True , ['Ctrl', 'Shift', 'U'], 'uncondjump.png', uncondjump),
    ('Undo Patch'       , False, ['Ctrl', 'Shift', 'Z'], None, undo),
    ('Redo Patch'       , False, ['Ctrl', 'Shift', 'Y'], None, redo),
    ('Save File'        , False, ['Ctrl', 'Shift', 'S'], None, savefile)
]


#Register hotkeys
for name, in_menu, keys, icon, func in hotkeys:
    idaapi.add_hotkey('-'.join(keys), func)


#Register menu items
if QtCore:
    qta = QtCore.QCoreApplication.instance()
    #XXX: This filter is too wide...
    menus = [i for i in qta.allWidgets() if isinstance(i, QtGui.QMenu) and i.title() == '' and i.actions() == []]

    qdata = []
    for name, in_menu, keys, icon, func in (i for i in hotkeys if i[1]):
        qact = QtGui.QAction(QtGui.QIcon(os.path.join(ftl_path, 'icons', icon)), name, qta)
        qact.triggered.connect(func)

        qks = QtGui.QKeySequence('+'.join(keys))
        qact.setShortcut(qks)
        qdata.append(qact)

    #Insert each entry into the context menu
    for i in menus:
        i.addSeparator()

        for qact in qdata:
            i.addAction(qact)
