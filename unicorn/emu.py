from __future__ import print_function
import binascii
from unicorn import *
from unicorn.x86_const import *
from capstone import *

ADDRESS = 0x0
md = Cs(CS_ARCH_X86, CS_MODE_32)
instructions = 0
start_inst = 0
end_inst = 0
next_is_rdtsc = False;

def emulate(input_file, main_start, main_end):
    try:
        global start_inst, end_inst, instructions
        start_inst = 0
        end_inst = 0
        print("Emulating x86_64")
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(ADDRESS, 0x300 * 0x400 * 0x400)

        in_file = open(input_file, "rb")
        data = in_file.read()
        in_file.close()

        mu.mem_write(ADDRESS, data)

        mu.reg_write(UC_X86_REG_EBP, 0x18000000)
        mu.reg_write(UC_X86_REG_ESP, 0x20000000)
        mu.reg_write(UC_X86_REG_GS, 0x10000000)
        instructions = 0
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.emu_start(ADDRESS+main_start, ADDRESS+main_end)

        print("Emulation done. Below is context")
        r_ebp = mu.reg_read(UC_X86_REG_EBP)
        r_eip = mu.reg_read(UC_X86_REG_EIP)
        print("EBP: " + hex(r_ebp))
        print("EIP: " + hex(r_eip))
        total_time = end_inst - start_inst
        print("Started: " + hex(start_inst))
        print("Ended:   " + hex(end_inst))
        print("Executed " + str(instructions) + " instructions")
        print("Total time: " + str(total_time))

        return total_time

    except UcError as e:
        print("ERROR: %s" % e)

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    global instructions
    global next_is_rdtsc
    global start_inst
    global end_inst
    instructions += 1
    instruction = uc.mem_read(address, size)
    instruction = bytes(instruction)
    for i in md.disasm(instruction, 0x0):
        # print("0x%08x:\t0x%032x \t%s\t%s" % (address, int.from_bytes(instruction, byteorder='big'), i.mnemonic, i.op_str))
        
        if (i.mnemonic == "rdtscp") or (next_is_rdtsc):
            r_eax = uc.reg_read(UC_X86_REG_EAX)
            r_edx = uc.reg_read(UC_X86_REG_EDX)
            if next_is_rdtsc:
                if start_inst == 0:
                    start_inst = r_edx << 32 | r_eax
                else:
                    end_inst = r_edx << 32 | r_eax
            r_gs = uc.reg_read(UC_X86_REG_GS)
            if next_is_rdtsc:
                print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
                print("EAX: " + '0x{0:0{1}X}'.format(r_eax, 8))
                print("EDX: " + '0x{0:0{1}X}'.format(r_edx, 8))
                print("GS: " + hex(r_gs))
                print("Executed " + str(instructions) + " instructions")
                print()
            if next_is_rdtsc:
                next_is_rdtsc = False
            if i.mnemonic == "rdtscp":
                next_is_rdtsc = True
        
