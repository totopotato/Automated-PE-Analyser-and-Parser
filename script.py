import idc
import idaapi
import idautils

idaapi.auto_wait()

dynamic_import = []
for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        m = idc.print_insn_mnem(line)
        if m == 'call' or m == 'jmp':
            op = idc.get_operand_type(line, 0)
            if op == o_reg:
                print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
                dynamic_import.append([line, idc.generate_disasm_line(line, 0)])

f = open("output.txt", 'w')
f.write(str(dynamic_import))
f.close()

idc.qexit(0)
