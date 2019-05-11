#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADDRESS 0x00

int main(int argc, char **argv, char **envp) {
	uc_engine *uc;
	uc_err err;
	
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed uc_open: %u\n", err);
		return -1;
	}

	uc_mem_map(uc, ADDRESS, 0x10000000, UC_PROT_ALL);
	printf("Emulating x86_64 code\n");

	FILE *open = fopen(argv[1], "rb");
	fseek(open, 0, SEEK_END);
	long fsize = ftell(open);
	fseek(open, 0, SEEK_SET);

	char *program_contents = malloc(fsize + 1);
	fread(program_contents, fsize, 1, open);
	fclose(open);
	printf("Read file of size %d\n", fsize);

	if (uc_mem_write(uc, ADDRESS, program_contents, fsize)) {
		printf("Failed to write emulation code, quitting.\n");
		return -1;
	}

	int start_esp = ADDRESS+fsize+0x100;
	uc_reg_write(uc, UC_X86_REG_ESP, &start_esp);

	printf("Starting emulation\n");

	err = uc_emu_start(uc, ADDRESS+0x8049000, ADDRESS+0x0804a098, 0, 0);

	if (err) {
		printf("Failed on uc_emu_start() with error %u: %s\n", err, uc_strerror(err));
	}
	
	unsigned char* output_vals = malloc(16);
	unsigned long output_addr = 0;
	uc_reg_read(uc, UC_X86_REG_EBP, &output_addr);
	output_addr -= 0x160;
	printf("Address: %08x\n", output_addr);
	uc_mem_read(uc, output_addr, output_vals, 16);
	printf("Chars: ");
	for (int i = 0; i < 16; i++) {
		printf("%02x", output_vals[i] & 0xFF);
	}
	printf("\n");

	uc_close(uc);
	free(output_vals);
	
	printf("Complete! \n");

	return 0;
}
