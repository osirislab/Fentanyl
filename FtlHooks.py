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
        if self.cmd in self.hooks:
            self.hooks[self.cmd]()
        return 0

    def register(self, name, func):
        self.hooks[name] = func
