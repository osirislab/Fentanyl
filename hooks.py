import ida_kernwin
import idaapi

import AssembleForm
import CodeCaveFinder
import Neuter
import Util
import Fentanyl
import traceback

ftl = Fentanyl.Fentanyl()
asf = AssembleForm.AssembleForm()
ftln = Neuter.Neuter(ftl)


def nopout():
    start, end = Util.get_pos()
    ftl.nopout(start, end - start)


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


# ------------------------------------------------------------------------------
# IDA ctxt
# ------------------------------------------------------------------------------

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


def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        os.path.abspath(ftl_path),
        "icons",
        resource_name
    )


HOOKS = [
    {
        'prefix': 'prefix:nop_out',
        'title': 'Nop out',
        'hook': IDACtxEntry(nopout),
        'hotkey': 'Ctrl+Alt+N',
        'desc': 'Nop out current instruction.',
        'icon': idaapi.load_custom_icon(plugin_resource('nopout.png'))
    },
    {
        'prefix': 'prefix:nop_xrefs',
        'title': 'Nop out Xrefs',
        'hook': IDACtxEntry(nopxrefs),
        'hotkey': 'Ctrl+Alt+X',
        'desc': 'Nop out current function Xrefs.',
        'icon': idaapi.load_custom_icon(plugin_resource('nopxrefs.png'))
    },
    {
        'prefix': 'prefix:assemble',
        'title': 'Assemble',
        'hook': IDACtxEntry(assemble),
        'hotkey': 'Ctrl+Alt+P',
        'desc': 'Patch instruction.',
        'icon': idaapi.load_custom_icon(plugin_resource('assemble.png'))
    },
    {
        'prefix': 'prefix:toggle_jump',
        'title': 'Toggle jmp',
        'hook': IDACtxEntry(togglejump),
        'hotkey': 'Ctrl+Alt+J',
        'desc': 'Invert conditional jump.',
        'icon': idaapi.load_custom_icon(plugin_resource('togglejump.png'))
    },
    {
        'prefix': 'prefix:force_jump',
        'title': 'Force jump',
        'hook': IDACtxEntry(uncondjump),
        'hotkey': 'Ctrl+Alt+F',
        'desc': 'Make jump unconditional.',
        'icon': idaapi.load_custom_icon(plugin_resource('uncondjump.png'))
    },
    {
        'prefix': 'prefix:undo',
        'title': 'Undo patch',
        'hook': IDACtxEntry(undo),
        'hotkey': 'Alt+Z',
        'desc': 'Undo last patch.'
    },
    {
        'prefix': 'prefix:redo',
        'title': 'Redo patch',
        'hook': IDACtxEntry(redo),
        'hotkey': 'Alt+Y',
        'desc': 'Redo last patch.'
    },
    {
        'prefix': 'prefix:save_patched',
        'title': 'Save Patched',
        'hook': IDACtxEntry(savefile),
        'hotkey': 'Ctrl+Alt+S',
        'desc': 'Save patched file.'
    },
    {
        'prefix': 'prefix:code_caves',
        'title': 'Code Caves',
        'hook': IDACtxEntry(openspelunky),
        'hotkey': 'Ctrl+Alt+C',
        'desc': 'Find code caves.'
    },
    {
        'prefix': 'prefix:neuter',
        'title': 'Neuter Binary',
        'hook': IDACtxEntry(neuter),
        'hotkey': 'Ctrl+Alt+N',
        'desc': 'Neuter the binary (remove calls to fork, setuid, setgid, getpwnam, setgroups, and chdir).'
    }
]
