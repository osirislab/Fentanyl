__AUTHOR__ = 'OSIRIS Lab'
PLUGIN_NAME = "Fentanyl"
VERSION = '2.0'

import idc
import idaapi
import idautils
import hooks

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore

    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return fentanyl()


class fentanyl(idaapi.plugin_t):
    """
    The IDA Plugin for Fentanyl.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Fentanyl - IDA Multitool"
    help = "Visit ... for help."
    wanted_name = PLUGIN_NAME

    # --------------------------------------------------------------------------
    # Plugin Overloads
    # --------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the menu actions our plugin will inject
        self._init_action_fentanyl()

        # initialize plugin hooks
        self._init_hooks()

        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_fentanyl()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    # --------------------------------------------------------------------------
    # Plugin Hooks
    # --------------------------------------------------------------------------

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    def _init_action_fentanyl(self):
        _hooks = [
            idaapi.action_desc_t(
                h['prefix'],
                h['title'],
                h['hook'],
                h['hotkey'],
                h['desc'],
                h['icon']
            ) if h['icon'] else idaapi.action_desc_t(
                h['prefix'],
                h['title'],
                h['hook'],
                h['hotkey'],
                h['desc']
            ) for h in hooks.HOOKS
        ]
        for action_desc in _hooks:
            idaapi.register_action(action_desc)

    def _del_action_copy_bytes(self):
        """
        Delete the bulk prefix action from IDA.
        """
        for h in hooks.HOOKS:
            idaapi.unregister_action(h['prefix'])


# ------------------------------------------------------------------------------
# Plugin Hooks
# ------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        We lump this under the (UI) Hooks class for organizational reasons.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            for h in hooks.HOOKS:
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    h['prefix'],
                    h['title'],
                    idaapi.SETMENU_APP
                )
        # done
        return 0


# ------------------------------------------------------------------------------
# Prefix Wrappers
# ------------------------------------------------------------------------------


# def inject_actions(form, popup, form_type):
#     """
#     Inject prefix actions to popup menu(s) based on context.
#     """
#
#     #
#     # disassembly window
#     #
#
#     if form_type == idaapi.BWN_DISASMS:
#         # insert the prefix action entry into the menu
#         #
#         for h in hooks.HOOKS:
#             idaapi.attach_action_to_popup(
#                 form,
#                 popup,
#                 h['prefix'],
#                 h['title'],
#                 idaapi.SETMENU_APP
#             )
#
#     # done
#     return 0
