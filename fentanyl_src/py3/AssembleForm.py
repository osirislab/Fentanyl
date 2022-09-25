"""
AssembleForm.py

Form for assembling into the IDB with Fentanyl. 

"""
import idaapi


class AssembleForm(object):
    """ Form elements for Fentanyl """

    def __init__(self):
        """ Initialize form elements """
        self.ui_cntls = {
            'inp': idaapi.Form.MultiLineTextControl('', idaapi.textctrl_info_t.TXTF_FIXEDFONT),
            'opt_chk': idaapi.Form.ChkGroupControl(('fixup', 'nopout')),
            'form_cb': idaapi.Form.FormChangeCb(self._form_cb),
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

        # Checkboxes get turned into a dict()
        if isinstance(cntl, idaapi.Form.ChkGroupControl):
            names = cntl.children_names
            opts = {}
            for i in range(len(names)):
                opts[names[i]] = val & (2 ** i)
            val = opts
        else:
            # MultiLineText controls require an extra step to get the text
            if isinstance(cntl, idaapi.Form.MultiLineTextControl):
                val = val.value
        return val

    def _form_cb(self, fid):
        """ Handle callbacks and grab control values """
        # Only continue if Assemble (OK) pressed
        if fid != -2:
            return

        self.values = dict([
            (k, self._getvalue(v))
            for k, v in self.ui_cntls.items()
            # Exclude the callback, it isn't a control
            if not isinstance(v, idaapi.Form.FormChangeCb)
        ])
        return True

    def process(self):
        """ Execute the form and return values """
        if not self.ui_form.Execute():
            self.values = None
        return self.values
