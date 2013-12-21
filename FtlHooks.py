"""
FtlHooks.py

Hooks to process various events.

"""

import idaapi

class FtlHooks(idaapi.UI_Hooks):
    def __init__(self):
        super(FtlHooks, self).__init__()
        self.cmd = None

    def preprocess(self, name):
        self.cmd = name
        return 0

    def postprocess(self):
        if self.cmd == 'CloseBase': pass
        elif self.cmd == 'LoadFile': pass
        #print("CMD> %s" % self.cmd)
        return 0

