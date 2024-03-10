#include "stdint.h"
#include "stdio.h"

int main(int argc, char** argv) {
	unsigned char cblock[17] = { 0x81, 0xEC, 0x70, 0x01, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57, 0x8B, 0xF9, 0x33, 0xC0, 0xB9, 0xDD, 0x00 };

*(cblock + 0) ^= *(cblock + 8);
*(cblock + 1) ^= *(cblock + 9);
*(cblock + 2) ^= *(cblock + 10);
*(cblock + 3) ^= *(cblock + 11);
*(cblock + 4) ^= *(cblock + 12);
*(cblock + 5) ^= *(cblock + 13);
*(cblock + 6) ^= *(cblock + 14);
*(cblock + 7) ^= *(cblock + 15);
*(cblock + 8) ^= *(cblock + 16);

	for (uint32_t i = 0; i < 16; i++) {
		printf("%02x\n", cblock[i]);
	}
}
