

#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
/*
 * Library Name: CRC16
 *
 * Filename: CRC16.cpp
 * Description: library CRC16 implementation
 *
 * generate a ccitt 16 bit cyclic redundancy check (crc)
 * The code in this module generates the crc for a block of data.
 *
 * Version: 1.0.2
 * Author: Joao Alves <jpralves@gmail.com>
 * Required files: crc16.cpp, crc16.h
 *
 * History:
 * 1.0.2 - 2017-03-14 - Initial Version
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


//                                 16  12  5
// The CCITT CRC 16 polynomial is X + X + X + 1.
// In binary, this is the bit pattern 1 0001 0000 0010 0001, and in hex it
//  is 0x11021.
// A 17 bit register is simulated by testing the MSB before shifting
//  the data, which affords us the luxury of specifiy the polynomial as a
//  16 bit value, 0x1021.

#define POLY 0x1021

uint16_t processByte(uint8_t data, uint16_t crc) {
  uint8_t i;

  crc = crc ^ ((uint16_t)data << 8);
  for (i = 0; i < 8; i++) {
    if (crc & 0x8000)
      crc = (crc << 1) ^ POLY;
    else
      crc <<= 1;
  }
  return crc;
}

uint16_t processBuffer(const char *data_p, uint16_t length) {
	uint16_t crc = 0xffff;
/*   for (uint32_t i = 0; i < 2; i++) {
    crc = processByte(0, crc);
  } */
  while(length--) {
    crc = processByte(*data_p++, crc);

  }
  return crc;
}

uint16_t adjusted(const char *data, uint32_t length) {
	uint8_t lsb = 0;
	uint8_t msb = 0;
	for (uint32_t i = 0; i < length; i++) {
		uint8_t x = data[i] ^ msb;
		uint8_t y = x ^ (x >> 4);
		msb = lsb ^ (y >> 3) ^ (y << 4);
		lsb = y ^ (y << 5);
	}
	msb = msb ^ 0xFF;
	lsb = lsb ^ 0xFF;
	return (msb << 8) | (lsb);
}


#include <limits.h>
#define CRCPOLY1  0x1021U  /* x^{16}+x^{12}+x^5+1 */
unsigned int crctable[UCHAR_MAX + 1];

void make_crc16_table(void)
{
	unsigned int i, j, r;

	for (i = 0; i <= UCHAR_MAX; i++) {
		r = i << (16 - CHAR_BIT);
		for (j = 0; j < CHAR_BIT; j++)
			if (r & 0x8000U) r = (r << 1) ^ CRCPOLY1;
			else             r <<= 1;
			crctable[i] = r & 0xFFFFU;
	}
}

unsigned int update_crc16(uint8_t c[], int n)
{
	unsigned int r;

//	r = 0xFFFFU;
	r = 0;
	while (--n >= 0)
		r = (r << CHAR_BIT) ^ crctable[(uint8_t)(r >> (16 - CHAR_BIT)) ^ *c++];
	return ~r & 0xFFFFU;
}


int main(int argc, char** argv) {
	make_crc16_table();
	 char* data1 = "\x01\x01\x04\x00\x33\x00\x04\x02\x33"; // cc67 expected_crc
	 char* data2 = "\x01\x01\x04\x00\x32\x00\x04\x02\x32"; // 7617 observed_crc

	 char* data3 = "\x01\x01\x04\x01\x33\x00\x04\x82\x33"; // 925f expected_crc
	 char* data4 = "\x01\x01\x04\x00\x33\x00\x04\x02\x33"; // cc67 observed_crc

	 char* data5 = "\x01\x01\x01\x06\x51\x00\x01\x08\x51"; // 2da1
	 char* data6 = "\x01\x01\x01\x06\x52\x00\x01\x08\x52"; // f310
	unsigned short crc1 = update_crc16(data5, 9);
	printf("%x\n", crc1);
	unsigned short crc2 = update_crc16(data6, 9);
	printf("%x\n", crc2);
}

/*
18182	04:02:32	41 01 01 04 00 33 00 04 02 33 d1 38    ba70 0000
expected subchannel 41 01 01 04 00 32 00 04 02 32

(expected_crc^observed_crc) = 0xba70


18183	04:02:33	41 01 01 04 01 33 00 04 82 33 51 39    8001 de39
expected subchannel 41 01 01 04 00 33 00 04 02 33

(expected_crc^observed_crc) = 0x5e38


*/
