import re
import idc, idaapi, idautils

def NopOut():
    ea = ScreenEA()
    size = ItemSize(ea)
    idc.MakeUnknown(ea, size, 0)
    for i in range(size):
        PatchByte(ea+i, 0x90)
        MakeCode(ea+i)

def SavePatchedFile():
    output_file = AskFile(1, "*", "Output File")
    idc.GenerateFile(idaapi.OFILE_DIF, output_file, 0, MaxEA(), 0)
    diff_file = open(output_file, "rb").read()
    orig_file = open(idc.GetInputFilePath(), "rb").read()

    diff_file = diff_file.split("\n")
    for line in diff_file:
        match = re.match("([A-F0-9]+): ([A-F0-9]+) ([A-F0-9]+)", line)
        if match:
            groups = match.groups()
            if orig_file[int(groups[0], 16)] == groups[1].decode('hex'):
                orig_file = orig_file[:int(groups[0], 16)] + groups[2].decode('hex') + orig_file[int(groups[0], 16)+1:]
            else:
                print "Error matching %02x at offset %x..." % (groups[1], groups[0])

    new_file = open(output_file, 'wb')
    new_file.write(orig_file)
    new_file.close()

def SingleAssemble():
    data = idaapi.asktext(9999, GetDisasm(ScreenEA()).split(";")[0], "Instruction")
    if not data:
        return

    data = data.replace("offset ", "")
    assembled = idautils.Assemble(ScreenEA(), data)
    if not assembled[0]:
        print "failures"
        return

    print assembled

    current_instruction = DecodeInstruction(ScreenEA())
    if len(assembled[1]) > current_instruction.size:
        if idaapi.askyn_c(0, "The assembled instruction is bigger than the current instruction. This may clobber following instructions. Continue?") != 1:
            return

    nop = idautils.Assemble(ScreenEA(), "nop")
    if not nop[0]:
        return

    padding = nop[1]*(max(0, current_instruction.size - len(assembled[1])))
    new_code = assembled[1] + padding

    print new_code

    idc.MakeUnknown(ScreenEA(), len(new_code), 0)

    print repr(new_code)

    for i in range(len(new_code)):
        print new_code[i]
        PatchByte(ScreenEA()+i, ord(new_code[i]))
    SetColor(ScreenEA()+i, CIC_ITEM, 0x00FF00)
        MakeCode(ScreenEA()+i)
        
    # idaapi.assemble(ScreenEA(), 0, ScreenEA(), 1, data)

def SwapJump():
    j = GetDisasm(ScreenEA()).split(";")[0]
    jump = j.split(" ")[0]
    if jump == "jnz":
        j = j.replace("jnz ", "jz ")
    elif jump == "jz":
        j = j.replace("jz ", "jnz ")

    idaapi.assemble(ScreenEA(), 0, ScreenEA(), 1, j)

def MakeUnconditional():
    j = GetDisasm(ScreenEA()).split(";")[0]
    jump = j.split(" ")[0]
    if jump in ["jnz", "jz", "jle"]:
        j = j.replace(jump, "jmp")

    idaapi.assemble(ScreenEA(), 0, ScreenEA(), 1, j)
