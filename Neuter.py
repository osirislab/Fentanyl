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
        
        setuids = idautils.XrefsTo(self.functions['.setuid']) #get calls to setuid
        for setuid in setuids:

            getpwnam = idautils.XrefsTo(self.functions['.getpwnam'])
            for x in getpwnam:
                if self.in_func(setuid.frm, x.frm):
                    self.replace_with(x.frm, ['mov eax, 1'])

            setgroups = idautils.XrefsTo(self.functions['.setgroups'])
            for x in setgroups:
                if self.in_func(setuid.frm, x.frm):
                    self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop'])

            setgid = idautils.XrefsTo(self.functions['.setgid'])
            for x in setgid:
                if self.in_func(setuid.frm, x.frm):
                    self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop'])

            setuid_call = idautils.XrefsTo(self.functions['.setuid'])
            for x in setuid_call:
                if self.in_func(setuid.frm, x.frm):
                    self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop'])

            chdir = idautils.XrefsTo(self.functions['.chdir'])
            for x in chdir:
                if self.in_func(setuid.frm, x.frm):
                    self.replace_with(x.frm, ['xor eax,eax', 'nop', 'nop', 'nop'])
            



