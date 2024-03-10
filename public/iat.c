#include <stdint.h>
#include <stdio.h>


/*
stack h



00D42420    51              PUSH ECX
	save ecx
00D42421    8B4424 10       MOV EAX,DWORD PTR SS:[ESP+10]		; tea key (32bit)
	move pointer_to_key into eax
00D42425    53              PUSH EBX
	save ebx
00D42426    8B5C24 0C       MOV EBX,DWORD PTR SS:[ESP+C]		; Allocated memory
	move pointer_to_start_of_allocated_data into ebx
00D4242A    55              PUSH EBP
	save ebp
00D4242B    56              PUSH ESI
	save esi
00D4242C    8B7424 18       MOV ESI,DWORD PTR SS:[ESP+18]		; Nb max api 0x99 or 0x5c
	put number_of_functions in esi
00D42430    33ED            XOR EBP,EBP
	set number_of_functions_obfuscated to zero
00D42432    33C9            XOR ECX,ECX
	set iteration_variable to zero
00D42434    57              PUSH EDI
	save edi
00D42435    8B38            MOV EDI,DWORD PTR DS:[EAX]
	move  key into edi



@loop_check_and_setup:
00D42437    3BF5            CMP ESI,EBP
	compare number_of_functions to intermixing_variable
00D42439    896C24 10       MOV DWORD PTR SS:[ESP+10],EBP
	write number_of_functions_obfuscated to stack variable @ ESP+10
00D4243D    76 11           JBE SHORT dplayerx.00D42450
	jump to 00D42450 if number_of_functions <= 0
00D4243F    33C0            XOR EAX,EAX
	set function_index to zero
@loop:
00D42441    41              INC ECX
	increase iteration_variable by one
00D42442    890483          MOV DWORD PTR DS:[EBX+EAX*4],EAX
	write value of function_index to pointer_to_start_of_allocated_data[function_index] (32bit entries)
00D42445    8BC1            MOV EAX,ECX
	move iteration_variable into function_index
00D42447    25 FFFF0000     AND EAX,0FFFF
	keep lower 16 bits of function_index (hint/ordinal)
00D4244C    3BC6            CMP EAX,ESI
	compare number_of_functions to function_index
00D4244E  ^ 72 F1           JB SHORT dplayerx.00D42441
	jump to 00D42441 if function_index is below number_of_functions

allocated_memory[N] pointed by EBX = [0, 1, 2, 3, 4, 5, 6, 7, ...] after this




00D42450    3BF5            CMP ESI,EBP
	compare number_of_functions to number_of_functions_obfuscated
00D42452    76 5E           JBE SHORT dplayerx.00D424B2
	jump to @end_of_procedure if number_of_functions <= 0




@mix_key:
00D42454    69FF 6D5AE835   IMUL EDI,EDI,35E85A6D
	multiply key with 0x35E85A6D (big endian)
00D4245A    33D2            XOR EDX,EDX
	set number_of_set_bits_in_nbfunc to zero
00D4245C    81C7 E9621936   ADD EDI,361962E9
	add 0x361962E9(big endian) to key
00D42462    85F6            TEST ESI,ESI
	check if number_of_functions is zero
00D42464    8BC6            MOV EAX,ESI
	move number_of_functions into eax as number_of_functions_temp
00D42466    74 05           JE SHORT dplayerx.00D4246D
	jump to @unnamed_label if number_of_functions is zero
@loop:
00D42468    42              INC EDX
	increase number_of_set_bits_in_nbfunc by one
00D42469    D1E8            SHR EAX,1
	number_of_functions_temp >>= 1
00D4246B  ^ 75 FB           JNZ SHORT dplayerx.00D42468
	jump to @loop if number_of_functions_temp is not zero

edx now contains number of set bits in number_of_functions
	0000  0 functions => 0
	0001  1 functions => 1
	0011  3 functions => 2
	0111  7 functions => 3
	1111 15 functions => 4
	etc



@unnamed_label:
00D4246D    81E2 FFFF0000   AND EDX,0FFFF
	limit number_of_set_bits_in_nbfunc to 65535
00D42473    8BC7            MOV EAX,EDI
	move updated_key into eax as jump_table_target_index
00D42475    8BCA            MOV ECX,EDX
	move number_of_set_bits_in_nbfunc into ecx as number_of_set_bits_in_nbfunc_temp
00D42477    D3E8            SHR EAX,CL
	shift bits in jump_table_target_index by lower 8 bits of number_of_set_bits_in_nbfunc_temp  (should be at most 16 so this is essentially the same as shr eax,  ecx)
00D42479    B9 20000000     MOV ECX,20
	store the value 32 in ecx
00D4247E    2BCA            SUB ECX,EDX
	subtract number_of_set_bits_in_nbfunc from 32 and store in ecx as 32_minus_number_of_set_bits_in_nbfunc
00D42480    0FAFC6          IMUL EAX,ESI
	multiply jump_table_target_index by number_of_functions
00D42483    D3E8            SHR EAX,CL
	shift bits in jump_table_target_index by lower 8 bits of 32_minus_number_of_set_bits_in_nbfunc  (should be at most 16 so this is essentially the same as shr eax,  ecx)
00D42485    8BCD            MOV ECX,EBP
	move number_of_functions_obfuscated into ecx as current_function_index
00D42487    81E1 FFFF0000   AND ECX,0FFFF
	truncate higher bits from current_function_index
00D4248D    3BC1            CMP EAX,ECX
	compare jump_table_target_index to current_function_index
00D4248F    74 14           JE SHORT dplayerx.00D424A5
	jump to @skip_intermixing if jump_table_target_index is equal to current_function_index and skip mixing


EAX is now jump_table_target_index
ECX is now current_function_index

00D42491    8B148B          MOV EDX,DWORD PTR DS:[EBX+ECX*4]
	load original_value for current_function_index into edx
00D42494    895424 20       MOV DWORD PTR SS:[ESP+20],EDX
	save original_value into stack_variable_0x20
00D42498    8B1483          MOV EDX,DWORD PTR DS:[EBX+EAX*4]
	load value for jump_table_target_index into edx
00D4249B    89148B          MOV DWORD PTR DS:[EBX+ECX*4],EDX
	save value for as value current_function_index
00D4249E    8B4C24 20       MOV ECX,DWORD PTR SS:[ESP+20]
	load original_value from stack_varaible_0x20
00D424A2    890C83          MOV DWORD PTR DS:[EBX+EAX*4],ECX
	save original_value as value for jump_table_index


@skip_intermixing
00D424A5    45              INC EBP
	increase number_of_functions_obfuscated
00D424A6    8BD5            MOV EDX,EBP
	store number_of_functions_obfuscated in edx as current_function_index
00D424A8    81E2 FFFF0000   AND EDX,0FFFF
	truncate higher bits from current_function_index in edx
00D424AE    3BD6            CMP EDX,ESI
	compare current_function_index to number_of_functions
00D424B0  ^ 72 A2           JB SHORT dplayerx.00D42454
	jump to @mix_key if current_function_index is less than number_of_functions



@end_of_procedure:
00D424B2    5F              POP EDI
00D424B3    5E              POP ESI
00D424B4    5D              POP EBP
00D424B5    5B              POP EBX
00D424B6    59              POP ECX
00D424B7    C3              RET
*/


int main(int argc, char** argv) {
	uint32_t key = 0x563B3039;
	uint32_t n = 153;
	uint32_t table[n];
	for (uint32_t i = 0; i < n; i++) {
		table[i] = i;
	}
	uint32_t s1 = 0;
	for (uint32_t l = n; l > 0; l >>= 1) {
		s1 += 1;
	}
	uint32_t s2 = 32 - s1;
	for (uint32_t i = 0; i < n; i++) {
		printf("i is: %u\n", i);
		key *= 0x35E85A6D;
		printf("%u\n", key);
		key += 0x361962E9;
		printf("%u\n", key);
		uint32_t target = key;
		printf("%u\n", target);
		target >>= s1;
		printf("%u\n", target);
		target *= n;
		printf("%u\n", target);
		target >>= s2;
		printf("%u\n", target);
		if (target != i) {
			uint32_t a = table[i];
			uint32_t b = table[target];
			table[i] = b;
			table[target] = a;
		}
	}
	for (uint32_t i = 0; i < n; i++) {
		printf("%u\n", table[i]);
	}
}
