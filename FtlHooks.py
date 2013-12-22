"""
FtlHooks.py

Hooks to process various events.

"""

import idaapi

class FtlHooks(idaapi.UI_Hooks):
    def __init__(self):
        super(FtlHooks, self).__init__()
        self.hooks = {}
        self.cmd = None

    def preprocess(self, name):
        self.cmd = name
        return 0

    def postprocess(self):
        if self.cmd == 'LoadFile' and 'lfh' in self.hooks:
            self.hooks['lfh']()
        return 0

    def loadfilehook(self, func):
        self.hooks['lfh'] = func
