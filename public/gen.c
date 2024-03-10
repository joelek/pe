#include "stdio.h"
#include "stdint.h"

 uint32_t data_20007080 = 0x6608FEB6; // badsq
 unsigned char data_0x20007820[9] = { 0 }; // seed

// next: check data in dll

int32_t sub_20001cea()
{
	int32_t eax_1 = ((data_20007080 * 0x343fd) + 0x269ec3);
	data_20007080 = eax_1;
	return ((eax_1 >> 0x10) & 0x7fff);
}


uint32_t sub_20001cd0(int32_t arg1)
{
	return (sub_20001cea() % arg1);
}

int32_t __stdcall sub_20001000(/* int32_t arg1, int32_t arg2 */)
{/*
	data_20007830 = arg1;
	data_2000782c = arg2;
	sub_20001cb0(); */
	int i = 0;
	do
	{
		*(i + data_0x20007820) = sub_20001cd0(0x100);
		i = (i + 1);
	} while (i < 9);
	return 1;
}
/*
int32_t sub_20001cb0()
{
	return sub_20001ce0(sub_20001d08(nullptr));
}
 */

int32_t __stdcall sub_415d90(int32_t arg1, int32_t arg2)
{
    char eax_1;
    char edx;
    edx = arg2;
    eax_1 = arg2;
    int32_t eax_7 = (arg1 << (((((eax_1 ^ edx) - edx) & 7) ^ edx) - edx));
    return (((eax_7 & 0xff00) >> 8) | eax_7);
}

int main(int argc, char** argv) {
	sub_20001000();
	for (uint32_t i = 0; i < 9; i++) {
		printf("%02x\n", data_0x20007820[i]);
	}

		printf("%02x\n", sub_415d90(0x81EC7001,0x00005355));
}
