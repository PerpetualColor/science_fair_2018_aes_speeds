import emu

time = 0
for i in range(1, 51):
    print("TEST #" + str(i))
    time += emu.emulate("../16_bit/implementation/bin/aes", 0x1090+0xA35, 0x1090+0x1054)
    print("RUNNING AVERAGE: " + str(time/i))
print("Average cycles: " + str(time/50))
