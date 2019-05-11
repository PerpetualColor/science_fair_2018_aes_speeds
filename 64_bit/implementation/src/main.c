// #include <stdlib.h>
#include <stdio.h>
// #include <sys/resource.h>
// #include <sys/time.h>

#define KEYLEN 2 // words
#define BLOCKLEN 2 // words
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

void KeyExpansion(unsigned char key[], unsigned long long key_schedule[]);
void RotWord(unsigned long long* n);
void AddRoundKey(int round, unsigned long long* state, unsigned long long key[]);
void SubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
void MixColumns(unsigned char* r);
static __inline__ unsigned long long current_instruction(void);
unsigned char* Cipher(unsigned char in[], unsigned long long key[]);

int main() {
	/* in 128-bit AES, the key is 128-bits, equal to 4 * KEYLEN 32-bit words */
	unsigned char key0[KEYLEN*8] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key1[KEYLEN*8] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key2[KEYLEN*8] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key3[KEYLEN*8] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char key4[KEYLEN*8] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	int i, j;
	unsigned char input0[BLOCKLEN*8] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input1[BLOCKLEN*8] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input2[BLOCKLEN*8] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input3[BLOCKLEN*8] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char input4[BLOCKLEN*8] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

	unsigned char* output;

	/* AES requires a different key for each round plus one for an initial process, requiring NUMROUNDS+1 keys, and each key requires BLOCKLEN 32-bit words*/
	unsigned long long key_schedule0[BLOCKLEN*(NUMROUNDS+1)];
	unsigned long long key_schedule1[BLOCKLEN*(NUMROUNDS+1)];
	unsigned long long key_schedule2[BLOCKLEN*(NUMROUNDS+1)];
	unsigned long long key_schedule3[BLOCKLEN*(NUMROUNDS+1)];
	unsigned long long key_schedule4[BLOCKLEN*(NUMROUNDS+1)];
	for (int i = 0; i < BLOCKLEN*(NUMROUNDS+1); i++) {
		key_schedule0[i] = 0;
		key_schedule1[i] = 0;
		key_schedule2[i] = 0;
		key_schedule3[i] = 0;
		key_schedule4[i] = 0;
	}

	unsigned long long start = current_instruction();

	KeyExpansion(key0, key_schedule0);

	
	
	for (int i = 0; i < BLOCKLEN*(NUMROUNDS+1); i++) {
		printf("%016llx ", key_schedule0[i]);
		if ((i+1) % 2 == 0) {
			printf("\n");
		}
	}
	
	

	output = Cipher(input0, key_schedule0);
	
	KeyExpansion(key1, key_schedule1);
	output = Cipher(input1, key_schedule1);
	KeyExpansion(key2, key_schedule2);
	output = Cipher(input2, key_schedule2);
	KeyExpansion(key3, key_schedule3);
	output = Cipher(input3, key_schedule3);
	KeyExpansion(key4, key_schedule4);
	output = Cipher(input4, key_schedule4);
	
	for (int i = 0; i < 16; i++) {
		printf("%02x ", output[i]);
		if ((i+1) % 4 == 0)
			printf("\n");
	}
	

	unsigned long long end = current_instruction();

	return 0;
}


/* credit to https://hero.handmade.network/forums/code-discussion/t/961-rdtsc_gcc_and_asm */
static __inline__ unsigned long long current_instruction(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi) : : "ecx");
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

/* expand out the initial key, they will be in reverse byte-order due to endianness */
void KeyExpansion(unsigned char key[KEYLEN*8], unsigned long long key_schedule[BLOCKLEN*(NUMROUNDS+1)]) {
	int i, j;
	unsigned short temp;

	/* copy the key as the first expanded key */
	key_schedule[0] = *(((unsigned long long*) key)+1);
	key_schedule[1] = *(((unsigned long long*) key));

	/* iterate 64 bits at a time, each key is 128 bits */
	for (i = KEYLEN+1; i < BLOCKLEN*(NUMROUNDS+1); i+= 2) {
		key_schedule[i] = ((unsigned int*) key_schedule)[2*i-5];
		/* KEYLEN words = 128 bits; the start of the next key */
		if ((i+1) % KEYLEN == 0) {
			RotWord(&key_schedule[i]);
			
			unsigned char* char_schedule = (unsigned char*) &(key_schedule[i]);
			char_schedule[0] = getSBoxValue(char_schedule[0]);
			char_schedule[1] = getSBoxValue(char_schedule[1]);
			char_schedule[2] = getSBoxValue(char_schedule[2]);
			char_schedule[3] = getSBoxValue(char_schedule[3]);
			

			char_schedule[0] ^= rcon[i/KEYLEN];

			
			key_schedule[i] ^= key_schedule[i - 2];
			unsigned long long high = key_schedule[i] ^ ((unsigned long long)key_schedule[i] >> 32);
			key_schedule[i] &= 0x00000000FFFFFFFF;
			key_schedule[i] |= (high << 32);

			key_schedule[i-1] |= (key_schedule[i] >> 32) ^ key_schedule[i-3];
			high = key_schedule[i-1] ^ (key_schedule[i-1] >> 32);
			key_schedule[i-1] &= 0x00000000FFFFFFFF;
			key_schedule[i-1] |= high << 32;

		}
		
		// key_schedule[i] ^= key_schedule[i-2];
		
	}
			
}

void RotWord(unsigned long long* n) {
	unsigned char tmp = *n;
	*n >>= 8;
	*n &= 0x0000000000FFFFFF;
	*n |= (tmp << 24) & 0x00000000FF000000;
}

unsigned char* Cipher(unsigned char in[4*BLOCKLEN], unsigned long long key[BLOCKLEN*(NUMROUNDS+1)*2]) {
	int i,j;
	unsigned char* state;
	int round;
	state = in;
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[i]);
		if ((i+1) % 4 == 0)
			printf("\n");
	}
	printf("\n");

	AddRoundKey(0, (unsigned long long*) state, key);
	
	for (round = 1; round < NUMROUNDS-1; round++) {
		SubBytes(state);
		
		ShiftRows(state);
		for (i = 0; i < 4; i++) {
			MixColumns(state+4*i);
		}
		
		AddRoundKey(round, (unsigned long long*) state, key);
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[i]);
		if ((i+1) % 4 == 0)
			printf("\n");
	}
	printf("\n");
		
	}
	
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(NUMROUNDS, (unsigned long long*) state, key);
	for (int i = 0; i < 16; i++) {
		printf("%02x ", state[i]);
		if ((i+1) % 4 == 0)
			printf("\n");
	}
	printf("\n");

	return state;
}

void AddRoundKey(int round, unsigned long long* state, unsigned long long key[BLOCKLEN*(NUMROUNDS+1)*4]) {
	int i;
	printf("%016llx %016llx = ", *state, key[2*round+1]);
	*(state+0) ^= key[2*round+1];
	*(state+1) ^= key[2*round];
	printf("%016llx\n", *state);
}

void SubBytes(unsigned char* state) {
	int i,j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			*(state+4*i+j) = getSBoxValue(*(state+4*i+j));
		}
	}
}

void ShiftRows(unsigned char* state) {
	int i, j;
	char temp;
	for (i = 1; i < 4; i++) {
		for (j = 4 - i; j < 4; j++) {
			/* columns are shifted instead of rows, due to the way the table is formatted */
			temp = *(state+i);
			*(state+i)=*(state+4+i);
			*(state+4+i)=*(state+8+i);
			*(state+8+i)=*(state+12+i);
			*(state+12+i) = temp;
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

	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

}
