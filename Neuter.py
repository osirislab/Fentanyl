import idaapi
import idautils
import idc


class Neuter(object):
    def __init__(self, ftl):
        self.ftl = ftl
        self.functions = {}
        for x in idautils.Functions():
            self.functions[idc.get_func_name(x)] = x

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
        if func.startEA <= addr <= func.endEA:
            return True
        return False

    def auto(self):
        """Automatically patch out annoying functions"""
        nop = ['xor eax,eax', 'nop', 'nop', 'nop']
        self.nop_xrefs('.alarm')
        self.replace_with('.fork', nop)

        # get funcs containing calls to setuid
        setuids = self.find_funcs('.setuid')

        for setuid in setuids:
            _functions = [('.getpwnam', ['mov eax, 1']), ('.setgroups', nop), ('.setgid', nop), ('.setuid', nop), ('.chdir', nop)]
            for _sub_x in _functions:
                for x in idautils.XrefsTo(self.functions[_sub_x[0]]):
                    if self.in_func(setuid, x.frm):
                        self.replace_with(x.frm, _sub_x[1])
