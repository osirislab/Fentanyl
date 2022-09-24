import idaapi
import idautils
import idc


class Neuter(object):
    def __init__(self, ftl):
        self.ftl = ftl
        self.functions = {}
        for x in idautils.Functions():
            self.functions[idc.get_func_name(x)] = x
        print(self.functions)

    def nop_xrefs(self, *funcs):
        """Nop out any xref to a function. """
        for x in funcs:
            func = self.functions.get(x, None)
            if func:
                self.ftl.nopxrefs(func)

    def replace_with(self, func, replace):
        """Replace an instruction"""
        if isinstance(func, int):
            return self.ftl.assemble(func, replace)
        _func = self.functions.get(func, None)
        if _func:
            xrefs = idautils.XrefsTo(_func)
            for x in xrefs:
                return self.ftl.assemble(x.frm, replace)

    def find_funcs(self, *funcs):
        """Find functions that call all funcs"""
        results = []
        for func in funcs:
            _func = self.functions.get(func, None)
            if _func:
                xrefs = idautils.XrefsTo(_func)
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
                func = self.functions.get(_sub_x[0], None)
                if func:
                    for x in idautils.XrefsTo(func):
                        if self.in_func(setuid, x.frm):
                            self.replace_with(x.frm, _sub_x[1])
