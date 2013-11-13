"""
idapatch.py

IDAPython script to patch binaries. 

IDAPython: https://code.google.com/p/idapython/
Helfpul if you want to run scripts on startup: https://code.google.com/p/idapython/source/browse/trunk/examples/idapythonrc.py

Alt F7 to load scripts

File > Produce file > Create DIF file
Edit > Patch program > Apply patches to input file

Keybindings:
    Shift-N: Convert instruction to nops
    Shift-J: Invert conditional jump
    Shift-P: Patch instruction
    Shift-Z: Undo modification (Won't always work. Should still be careful editting.)

"""


from idautils import *
from ctypes import *
import idaapi

JUMPS = {
    'jns': 'js',
    'jnp': 'jp', 
    'jnz': 'jz', 
    'jle': 'jnle', 
    'jnb': 'jb', 
    'jnae': 'jae', 
    'jng': 'jg', 
    'jne': 'je', 
    'jno': 'jo', 
    'jnl': 'jl', 
    'jge': 'jnge', 
    'jnle': 'jle', 
    'jae': 'jnae', 
    'jz': 'jnz', 
    'jp': 'jnp', 
    'js': 'jns', 
    'jl': 'jnl', 
    'jo': 'jno', 
    'jnbe': 'jbe', 
    'je': 'jne', 
    'jg': 'jng', 
    'ja': 'jna', 
    'jb': 'jnb', 
    'jc': 'jnc', 
    'jnc': 'jc', 
    'jnge': 'jge', 
    'jna': 'ja', 
    'jbe': 'jnbe'
}

UNDO = [] # (int of address, list of opcodes at address)
def undo():
    if len(UNDO) > 0:
        inst = UNDO.pop()
        MakeUnknown(inst[0], len(inst[1]), 0)
        for i in range( len( inst[1] ) ):
            PatchByte( inst[0] + i, inst[1][i])
            MakeCode(inst[0] + i)
        idaapi.jumpto(inst[0])
        return True
    Warning('Nothing to undo')
    
def opcodes(ea = False):
    if not ea:
        ea = ScreenEA()
    opcodes = []
    size = ItemSize(ea)
    for i in range(size):
        opcodes.append(Byte(ea + i))
    return opcodes

def nop_all_the_xrefs(ea=False):
    if not ea:
        ea = ScreenEA()
    for xref in XrefsTo(ea, 0):
        convert_to_nop(xref.frm, True)

def patch_instruction(ea=False):
    if not ea:
        ea = ScreenEA()
    inst = DecodeInstruction(ea)
    value = GetDisasm(ea).split(';')[0].rstrip()
    user_inst = AskStr(value, "Patch")
    if user_inst:
        UNDO.append((ea, opcodes(ea)))
        if not idaapi.assemble(ea, 0, 0, True, user_inst):
            UNDO.pop()            
    else:
        return False

def invert_jump(ea=False):
    if not ea:
        ea = ScreenEA()
    mnem = GetMnem(ea)
    inst = DecodeInstruction(ea)
    if mnem in JUMPS:
        UNDO.append((ea, opcodes(ea))) ## UNDO
        if not idaapi.assemble(ea, inst.cs, inst.ip, True, GetDisasm(ea).replace(mnem, JUMPS[mnem]) ):
            UNDO.pop()
    else:
        Warning("Not a conditional jump")
        return False

def force_jump(ea=False):
    if not ea:
        ea = ScreenEA()
    mnem = GetMnem(ea)
    inst = DecodeInstruction(ea)
    if mnem in JUMPS:
        UNDO.append((ea, opcodes(ea)))
        if not idaapi.assemble(ea, inst.cs, inst.ip, True, GetDisasm(ea).replace(mnem, "jmp") ):
            UNDO.pop()
    else:
        Warning("Not a conditional jump")
        return False

def convert_to_nop(ea=False, auto=False):
    if not ea:
        ea = ScreenEA()
    inst = DecodeInstruction(ea)
    if auto or AskYN(0, "Convert Instruction to NOP?") == 1:
        UNDO.append((ea, opcodes(ea))) 
        MakeUnknown(ea, inst.size, 0)
        for x in range(inst.size):
            if not idaapi.assemble(ea + x, inst.cs, inst.ip, True, 'nop'):
                UNDO.pop()
            MakeCode(ea + x)

def bulk_nop(start = False, end = False):
    if not (start or end):
        distance = SelEnd()-SelStart()
    else:
        distance = end - start
    ea = SelStart()
    for x in range(distance):
        convert_to_nop(ea + x, True)

idaapi.add_hotkey("Shift-N", convert_to_nop)
idaapi.add_hotkey("Shift-J", invert_jump)
idaapi.add_hotkey("Shift-P", patch_instruction)
idaapi.add_hotkey("Shift-Z", undo)
