"""
Util.py

Various helper functions

"""

import re
import idc
import ida_ua
import idaapi
import ida_bytes
import ida_ida


def instr_size(ea):
    """ Get the size of the instr at ea or 1 """
    insn = ida_ua.insn_t()
    instr = ida_ua.decode_insn(insn, ea)
    return instr if instr else 1


def get_pos():
    """ Get the selected area """
    start, end = idc.read_selection_start(), idc.read_selection_end()
    if start == idc.BADADDR:
        start = idc.get_screen_ea()
        end = idc.get_screen_ea() + instr_size(start)
    return start, end


def read_data(ea, sz):
    """ Read bytes from idb """
    return idaapi.get_bytes(ea, sz)


def write_data(ea, blob, reanalyze=True):
    """ Write bytes to idb """
    if reanalyze:
        idc.del_items(ea, len(blob), 0)
    ida_bytes.patch_bytes(ea, blob)
    if reanalyze:
        idc.create_insn(ea)


def save_file(output_file):
    """ Save the patched file """
    DIFF_RE = re.compile(r'([A-F0-9]+): ([A-F0-9]+) ([A-F0-9]+)')

    idc.gen_file(idaapi.OFILE_DIF, output_file, 0, ida_ida.inf_get_max_ea(), 0)
    diff_file = open(output_file, "rb").read()
    orig_file = open(idc.get_input_file_path(), "rb").read()
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
            orig_byte = bytes.fromhex(groups[1])
            new_byte = bytes.fromhex(groups[2])
            if orig_file[offset] == orig_byte[0]:
                orig_file = orig_file[:offset] + new_byte + orig_file[offset + 1:]
                success += 1
            else:
                print(f"Error matching {groups[1]} at offset %x..." % offset)

    new_file = open(output_file, 'wb')
    new_file.write(orig_file)
    new_file.close()
    print("%i/%i patches applied" % (success, total))
