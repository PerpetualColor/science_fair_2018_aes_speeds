import emu

time = 0
for i in range(1, 51):
    print("TEST #" + str(i))
    time += emu.emulate("../64_bit/implementation/bin/aes", 0x10B0+0xAA5, 0x10B0+0xAA5+0x483)
    print("RUNNING AVERAGE: " + str(time/i))
print("Average cycles: " + str(time/50))
# emu.emulate("../64_bit/implementation/bin/aes", 0x10B0+0xAA5, 0x10B0+0xAA5+0x483)
