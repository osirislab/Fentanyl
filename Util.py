"""
Util.py

Various helper functions

"""

import re
import idc
import idautils
import idaapi


def instr_size(ea):
    """ Get the size of the instr at ea or 1 """
    instr = idautils.DecodeInstruction(ea)
    # If invalid, return 1 to consume this byte
    # XXX: Fixed-width instr sets should add instr size
    return instr.size if instr else 1


def get_pos():
    """ Get the selected area """
    start, end = idc.SelStart(), idc.SelEnd()
    if start == idc.BADADDR:
        start = idc.ScreenEA()
        end = idc.ScreenEA() + instr_size(start)
    return start, end


def read_data(ea, sz):
    """ Read bytes from idb """
    return idaapi.get_many_bytes(ea, sz)


def write_data(ea, blob, reanalyze=True):
    """ Write bytes to idb """
    if reanalyze:
        idc.MakeUnknown(ea, len(blob), 0)
    idaapi.patch_many_bytes(ea, blob)
    if reanalyze:
        idc.MakeCode(ea)


def save_file(output_file):
    """ Save the patched file """
    DIFF_RE = re.compile(r'([A-F0-9]+): ([A-F0-9]+) ([A-F0-9]+)')

    idc.GenerateFile(idaapi.OFILE_DIF, output_file, 0, idc.MaxEA(), 0)
    diff_file = open(output_file, "rb").read()
    orig_file = open(idc.GetInputFilePath(), "rb").read()
    print("OK")
    diff_file = diff_file.split(b"\n")
    total = 0
    success = 0
    for line in diff_file:
        match = DIFF_RE.match(line.decode("utf-8"))
        if match:
            groups = match.groups()
            total += 1
            offset = int(groups[0], 16)
            orig_byte = groups[1].decode('hex')
            new_byte = groups[2].decode('hex')
            if orig_file[offset] == orig_byte:
                orig_file = orig_file[:offset] + new_byte + orig_file[offset + 1:]
                success += 1
            else:
                print("Error matching %02x at offset %x..." % (groups[1], offset))

    new_file = open(output_file, 'wb')
    new_file.write(orig_file)
    new_file.close()
    print("%i/%i patches applied" % (success, total))
