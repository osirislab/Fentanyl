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
import ida_kernwin
import Fentanyl
import AssembleForm
import FtlHooks
import CodeCaveFinder
import Util
import Neuter
from hooks import HOOKS

try:
    from PyQt5 import QtGui, QtWidgets, QtCore
except ImportError:
    print("PySide unavailable, no GUI")
    QtCore = None
    QtGui = None

""" Main """
ftl_path = os.path.dirname(__file__)

ftl = Fentanyl.Fentanyl()
asf = AssembleForm.AssembleForm()
ftlh = FtlHooks.FtlHooks()
ftln = Neuter.Neuter(ftl)
ftlh.hook()

# XXX: Store the parents of the QWidgets. Otherwise, some get GCed.
hack = []


# Interfaces to the methods in ftl
def nopout():
    start, end = Util.get_pos()
    ftl.nopout(start, end - start)


import traceback


def assemble():
    try:
        assemble_()
    except:
        print(traceback.format_exc())


def assemble_():
    success = False
    while not success:
        v = asf.process()
        if not v or not v['inp'].strip(): return

        start, end = Util.get_pos()
        lines = [i.strip() for i in v['inp'].replace(';', '\n').strip().split('\n')]
        success, data = ftl.assemble(start, lines, v['opt_chk']['fixup'], v['opt_chk']['nopout'])
        print(success, data)
        if not success:
            print(data)


def togglejump():
    start, end = Util.get_pos()
    ftl.togglejump(start)


def uncondjump():
    start, end = Util.get_pos()
    ftl.uncondjump(start)


def nopxrefs():
    start, end = Util.get_pos()
    func = idaapi.get_func(start)
    if func:
        ftl.nopxrefs(func.startEA)


def undo():
    if ftl.undo() is None:
        print("Nothing to undo")


def redo():
    if ftl.redo() is None:
        print("Nothing to redo")


def savefile():
    output_file = ida_kernwin.ask_file(1, "*", "Output File")
    if not output_file:
        return
    Util.save_file(output_file)


# Interface to spelunky
def openspelunky():
    window = CodeCaveFinder.CodeCaveWindow()
    window.Show("Spelunky")


def neuter():
    ftln.auto()


# Helper functions
def bind_ctx_menus():
    # Find all the menus we need to modify
    menus = []
    for wid in qta.allWidgets():
        if not isinstance(wid, QtWidgets.QMenu):
            continue

        parent = wid.parent()
        if parent.__class__ != QtWidgets.QWidget:
            continue
        print(parent.windowTitle())
        # Find Hex/IDA Views
        if 'Hex View' in parent.windowTitle() or 'IDA View' in parent.windowTitle() or len(parent.windowTitle()) == 1:
            hack.append(parent)
            menus.append(wid)

    # Filter out menus with actions
    menus = [i for i in menus if not i.actions()]

    print('Bound entries to %s' % menus)

    # Insert each entry into the context menu
    for i in range(len(menus)):
        menu = menus[i]
        menu.addSeparator()

        for qact in qdata:
            menu.addAction(qact)


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return fentanyl()


class fentanyl(idaapi.plugin_t):
    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        self._menu()

    def _menu(self):
        hotkeys = [
            idaapi.action_desc_t(

            ) for h in HOOKS
        ]
        hotkeys_new = [
            idaapi.action_desc_t(
                'prefix:nop_out',
                'Nop out',
                IDACtxEntry(nopout),
                'Ctrl+Alt+N',
                'Nop out current instruction.',
                idaapi.load_custom_icon(plugin_resource('nopout.png'))

            ),
            idaapi.action_desc_t(
                'prefix:nop_xrefs',
                'Nop out Xrefs',
                IDACtxEntry(nopxrefs),
                'Ctrl+Alt+X',
                'Nop out current function Xrefs.',
                idaapi.load_custom_icon(plugin_resource('nopxrefs.png'))
            ),
            idaapi.action_desc_t(
                'prefix:assemble',
                'Assemble',
                IDACtxEntry(assemble),
                'Ctrl+Alt+P',
                'Patch instruction.',
                idaapi.load_custom_icon(plugin_resource('assemble.png'))
            ),
            idaapi.action_desc_t(
                'prefix:toggle_jump',
                'Toggle jmp',
                IDACtxEntry(togglejump),
                'Ctrl+Alt+J',
                'Invert conditional jump.',
                idaapi.load_custom_icon(plugin_resource('togglejump.png'))
            ),
            idaapi.action_desc_t(
                'prefix:force_jump',
                'Force jump',
                IDACtxEntry(uncondjump),
                'Ctrl+Alt+F',
                'Make jump unconditional.',
                idaapi.load_custom_icon(plugin_resource('uncondjump.png'))
            ),
            idaapi.action_desc_t(
                'prefix:undo',
                'Undo patch',
                IDACtxEntry(undo),
                'Alt+Z',
                'Undo last patch.'
            ),
            idaapi.action_desc_t(
                'prefix:redo',
                'Redo patch',
                IDACtxEntry(redo),
                'Alt+Y',
                'Redo last patch.'
            ),
            idaapi.action_desc_t(
                'prefix:save_patched',
                'Save Patched',
                IDACtxEntry(savefile),
                'Ctrl+Alt+S',
                'Save patched file.'
            ),
            idaapi.action_desc_t(
                'prefix:code_caves',
                'Code Caves',
                IDACtxEntry(openspelunky),
                'Ctrl+Alt+C',
                'Find code caves.'
            ),
            idaapi.action_desc_t(
                'prefix:neuter',
                'Neuter Binary',
                IDACtxEntry(neuter),
                'Ctrl+Alt+N',
                'Neuter the binary (remove calls to fork, setuid, setgid, getpwnam, setgroups, and chdir).'
            )

        ]
        for action_desc in hotkeys_new:
            idaapi.register_action(action_desc)


class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_actions(form, popup, idaapi.get_tform_type(form))
        return 0

# Hotkey definitions
hotkeys = [('Replace with nops', True, ['Alt', 'N'], 'nopout.png', nopout),
    ('Nops all Xrefs', True, ['Alt', 'X'], 'nopxrefs.png', nopxrefs),
    ('Assemble', True, ['Alt', 'P'], 'assemble.png', assemble),
    ('Toggle jump', True, ['Alt', 'J'], 'togglejump.png', togglejump),
    ('Force jump', True, ['Ctrl', 'Alt', 'F'], 'uncondjump.png', uncondjump),
    ('Undo Patch', False, ['Alt', 'Z'], None, undo),
           ('Redo Patch', False, ['Alt', 'Y'], None, redo),
    ('Save File', False, ['Alt', 'S'], None, savefile),
           ('Find Code Caves', False, ['Alt', 'C'], None, openspelunky),
    ('Neuter Binary', False, ['Ctrl', 'Alt', 'N'], None, neuter)]

# Register hotkeys
for name, in_menu, keys, icon, func in hotkeys:
    idaapi.add_hotkey('-'.join(keys), func)

# Register menu items
if QtCore:
    qta = QtCore.QCoreApplication.instance()

    qdata = []
    for name, in_menu, keys, icon, func in (i for i in hotkeys if i[1]):
        qact = QtWidgets.QAction(QtGui.QIcon(os.path.join(ftl_path, 'icons', icon)), name, qta)
        qact.triggered.connect(func)

        qks = QtGui.QKeySequence('+'.join(keys))
        qact.setShortcut(qks)
        qdata.append(qact)

    bind_ctx_menus()

# Rebind on new db
ftlh.register('LoadFile', bind_ctx_menus)
# Rebind on new IDA View
ftlh.register('WindowOpen', bind_ctx_menus)
ftlh.register('GraphNewProximityView', bind_ctx_menus)
# Rebind on new Hex View
ftlh.register('ToggleDump', bind_ctx_menus)
# Reset on IDB close
ftlh.register('CloseBase', ftl.clear)
