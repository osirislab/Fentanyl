import idaapi
import idautils
import idc
import re
from Util import *

class Neuter(object):
    def __init__(self, ftl):
        self.ftl = ftl
        self.functions = {}
        for x in idautils.Functions():
            self.functions[idc.GetFunctionName(x)] = x

    def nop_xrefs(self, *funcs):
        """Nop out any xref to a function. """
        for x in funcs:
            self.ftl.nopxrefs(self.functions[x])

    def replace_with(self, func, replace):
        """Replace an instruction"""
        if type(func) == int or type(func) == long:
            return self.ftl.assemble(func, replace)
        xrefs = idautils.XrefsTo(self.functions[func])
        for x in xrefs:
            return self.ftl.assemble(x.frm, replace)

    def find_funcs(self, *funcs):
        """Find functions that call all funcs"""
        results = []
        for func in funcs:
            xrefs = idautils.XrefsTo(self.functions[func])
            for xref in xrefs:
                results.append(idaapi.get_func(xref.frm).startEA)
        results = list(set(results))
        return results

    def in_func(self, func, addr):
        """Check if an instruction is within a function"""
        func = idaapi.get_func(func)
        if addr >= func.startEA and addr <= func.endEA:
            return True
        return False

    def auto(self):
        """Automatically patch out annoying functions"""
        self.nop_xrefs('.alarm')
        self.replace_with('.fork', ['xor eax,eax', 'nop', 'nop', 'nop'])
        
        setuids = self.find_funcs('.setuid') #get funcs containing calls to setuid

        for setuid in setuids:
            getpwnams = [self.replace_with(x.frm, ['mov eax, 1']) for x in idautils.XrefsTo(self.functions['.getpwnam']) if self.in_func(setuid, x.frm)]
            setgroups = [self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop']) for x in idautils.XrefsTo(self.functions['.setgroups']) if self.in_func(setuid, x.frm)]
            setgids = [self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop']) for x in idautils.XrefsTo(self.functions['.setgid']) if self.in_func(setuid, x.frm)]
            setuids = [self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop']) for x in idautils.XrefsTo(self.functions['.setuid']) if self.in_func(setuid, x.frm)]
            chdirs = [self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop']) for x in idautils.XrefsTo(self.functions['.chdir']) if self.in_func(setuid, x.frm)]