// #include <stdlib.h>
// #include <stdio.h>
// #include <sys/resource.h>
// #include <sys/time.h>

#define KEYLEN 4 // words
#define BLOCKLEN 4 // words
#define NUMROUNDS 10 // rounds

/* calculating the sbox and rcon is beyond the complexity of this project. Credit to https://github.com/kokke/tiny-AES-c/blob/master/aes.c */
static const unsigned char sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const unsigned char rcon[11] = {
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getSBoxValue(num) (sbox[(num)])

void KeyExpansion(unsigned char key[], unsigned short key_schedule[]);
void RotWord(unsigned short* n);
void AddRoundKey(int round, unsigned short* state, unsigned short key[]);
void SubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
void MixColumns(unsigned char* r);
static __inline__ unsigned long long current_instruction(void);
unsigned char* Cipher(unsigned char in[], unsigned short key[]);

int main() {
	/* set highest priority for highest accuracy */
// 	setpriority(PRIO_PROCESS, 0, -20);

	/* in 128-bit AES, the key is 128-bits, 16 chars, equal to 4 * KEYLEN 32-bit words */
	unsigned char key0[KEYLEN*4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key1[KEYLEN*4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key2[KEYLEN*4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key3[KEYLEN*4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key4[KEYLEN*4] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	int i, j;
	unsigned char input0[BLOCKLEN*4] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input1[BLOCKLEN*4] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input2[BLOCKLEN*4] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input3[BLOCKLEN*4] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input4[BLOCKLEN*4] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

	unsigned char* output;

	/* AES requires a different key for each round plus one for an initial process, requiring NUMROUNDS+1 keys, and each key requires BLOCKLEN 32-bit words, or BLOCKLEN*2 16-bit words (unsigned shorts)*/
	unsigned short key_schedule[BLOCKLEN*(NUMROUNDS+1)*2];
	for (i = 0; i < BLOCKLEN*(NUMROUNDS+1)*2; i++) {
		key_schedule[i] = 0;
	}

	/* switch endianness of input array for processing */
	for (i = 0; i < BLOCKLEN*2; i++) {
		*((unsigned short*)input0+i) = (*((unsigned short*)input0+i)>>8) | (*((unsigned short*)input0+i)<<8);
		*((unsigned short*)input1+i) = (*((unsigned short*)input1+i)>>8) | (*((unsigned short*)input1+i)<<8);
		*((unsigned short*)input2+i) = (*((unsigned short*)input2+i)>>8) | (*((unsigned short*)input2+i)<<8);
		*((unsigned short*)input3+i) = (*((unsigned short*)input3+i)>>8) | (*((unsigned short*)input3+i)<<8);
		*((unsigned short*)input4+i) = (*((unsigned short*)input4+i)>>8) | (*((unsigned short*)input4+i)<<8);
	}

	unsigned long long start = current_instruction();
	// __asm__ __volatile__ ("rdtscp" : : : "eax", "edx", "ecx");

	KeyExpansion(key0, key_schedule);
	output = Cipher(input0, key_schedule);
	KeyExpansion(key1, key_schedule);
	output = Cipher(input1, key_schedule);
	KeyExpansion(key2, key_schedule);
	output = Cipher(input2, key_schedule);
	KeyExpansion(key3, key_schedule);
	output = Cipher(input3, key_schedule);
	KeyExpansion(key4, key_schedule);
	output = Cipher(input4, key_schedule);

	// __asm__ __volatile__ ("rdtscp" : : : "eax", "edx", "ecx");
	unsigned long long end = current_instruction();
	// printf("Total time: %llu\n", end - start);

	/*
	for (i = 0; i < 8; i+= 2) {
	printf("%04x %04x\n", *((unsigned short*) output+i), *((unsigned short*) output+i+1));
	}
	*/

	// printf("\n");

	return 0;
}

/* credit to https://hero.handmade.network/forums/code-discussion/t/961-rdtsc_gcc_and_asm */
static __inline__ unsigned long long current_instruction(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi) : : "ecx");
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

void KeyExpansion(unsigned char key[KEYLEN*4], unsigned short key_schedule[BLOCKLEN*(NUMROUNDS+1)*2]) {
	int i;
	unsigned short temp;

	for (i = 0; i < KEYLEN; i++) { // fill all the key_schedule values from 0 to 8 (4 words)
		key_schedule[i*2] = (key[4*i] << 8) | key[4*i+1];
		key_schedule[i*2+1] = (key[4*i+2] << 8) | key[4*i+3];
	}

	for (i = KEYLEN*2; i < BLOCKLEN*(NUMROUNDS+1)*2; i += 2) { // iterate 32 bits at a time
		key_schedule[i] = key_schedule[i-2];
		key_schedule[i+1] = key_schedule[i-1];
		if (i % (KEYLEN*2) == 0) { // start of the next key
			RotWord(&key_schedule[i-2]);

			key_schedule[i] = getSBoxValue(key_schedule[i] & 0x00FF) | (getSBoxValue(key_schedule[i] >> 8) << 8);
			key_schedule[i+1] = getSBoxValue(key_schedule[i+1] & 0x00FF) | (getSBoxValue(key_schedule[i+1] >> 8) << 8);
			key_schedule[i] ^= rcon[(i/2)/KEYLEN] << 8;
		}

		key_schedule[i] ^= key_schedule[i-(KEYLEN*2)];
		key_schedule[i+1] ^= key_schedule[i+1-(KEYLEN*2)];
	}
}

void RotWord(unsigned short* n) {
	*(n+3) = (*n >> 8) | (*(n+1) << 8 & 0x0000FFFF);
	*(n+2) = (*(n+1) >> 8) | (*n << 8 & 0x0000FFFF);
}

unsigned char* Cipher(unsigned char in[4*BLOCKLEN], unsigned short key[BLOCKLEN*(NUMROUNDS+1)*2]) {
	int i,j;
	unsigned char* state;
	int round;
	state = in;
	AddRoundKey(0, (unsigned short*) state, key);

	for (round = 1; round < NUMROUNDS; round++) {
		SubBytes(state);
		ShiftRows(state);
		for (i = 0; i < 4; i++) {
			MixColumns(state+4*i);
		}
		AddRoundKey(round, (unsigned short*) state, key);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(NUMROUNDS, (unsigned short*) state, key);


	return state;
}

void AddRoundKey(int round, unsigned short* state, unsigned short key[BLOCKLEN*(NUMROUNDS+1)*2]) {
	int i;
	for (i = 0; i < 8; i++) {
		*(state+i) ^= key[8*round+i];
	}
}

void SubBytes(unsigned char* state) {
	int i,j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			*(state+i*4+j) = getSBoxValue(*(state+i*4+j));
		}
	}
}

void ShiftRows(unsigned char* state) {
	/* because of the way the table is formatted, columns instead of rows are shifted */
	int i, j;
	int off; // required to fix endianness
	char temp;
	for (i = 1; i < 4; i++) {
		for (j = 4 - i; j < 4; j++) {
			/* perform a single shift */
			off = i % 2;
			if (off == 0) {
				off++;
			}
			else if (off == 1) {
				off = -1;
			}

			temp = *(state+i+off);
			*(state+i+off)=*(state+4+i+off);
			*(state+4+i+off)=*(state+8+i+off);
			*(state+8+i+off)=*(state+12+i+off);
			*(state+12+i+off) = temp;

		}
	}
}

/* large credit to https://en.wikipedia.org/wiki/Rijndael_MixColumns */
void MixColumns(unsigned char* r) {
	unsigned char a[4];
	unsigned char b[4];
	unsigned char c, h;
	
	/* copy r into a, and 2*a into b before limiting b to the Rijndael GF */
	
	for (c = 0; c < 4; c++) {
		a[c] = r[c];
		h = (unsigned char)((signed char)r[c] >> 7);
		b[c] = r[c] << 1;
		b[c] ^= 0x1b & h;

	}

	r[1] = b[1] ^ a[2] ^ a[3] ^ b[0] ^ a[0];
	r[0] = b[0] ^ a[1] ^ a[2] ^ b[3] ^ a[3];
	r[3] = b[3] ^ a[0] ^ a[1] ^ b[2] ^ a[2];
	r[2] = b[2] ^ a[3] ^ a[0] ^ b[1] ^ a[1];

}
