import * as fs from "fs";
import * as pe from "./pe";
import { Chunk } from "@joelek/ts-stdlib/dist/lib/data/chunk";

function multipleOf(number: number, multiple: number): number {
	return Math.ceil(number / multiple) * multiple;
};

/*

first pass combines xor tables into xor_Table_a
	XOR_TABLE_A[0] ? => ?
second pass:
	each index in xor_Table_a is processed 9 times, pass index 4 is special and updates variable_a to variable_a - 0x15 (0x42 became 0x2D)
	updates XOR_TABLE_A[0] from 0x0F to mixBytes(0x0F, ?) = 0x3C
	updates XOR_TABLE_A[0] from 0x3C to mixBytes(0x3C, 0xF4) = 0xC3
	updates XOR_TABLE_A[0] from 0xC3 to mixBytes(0xC3, 0xDA) = 0x0F
	updates XOR_TABLE_A[0] from 0x0F to mixBytes(0x0F, 0xC1) = 0x1E
	updates XOR_TABLE_A[0] from 0x1E to mixBytesPre(0x1E, 0x1F) = mixBytes(0x1E, 8 - (0x1F & 7)) = 0x3C
	updates XOR_TABLE_A[0] from 0x3C to mixBytes(0x3C, 0x6D) = 0x87
	updates XOR_TABLE_A[0] from 0x87 to mixBytes(0x87, 0x4C) = 0x78
	updates XOR_TABLE_A[0] from 0x78 to mixBytes(0x78, 0x2F) = 0x3C
	updates XOR_TABLE_A[0] from 0x3C to mixBytes(0x3C, 0x0F) = 0x1E
third pass finalizes xor_Table_a[0] with constant_a and constant_b
	XOR_TABLE_A[0] 0x1E => 0xCB
fourth pass checks if current address is pointer address (it is not) skips four bytes if pointer, uses byte from decrypted disc id (UKD_554900.001)
	updates BUFFER[0] from 0xB8 to 0xB8 ^ XOR_TABLE_A[0] => 0x73
	updates BUFFER[0] from 0x73 to 0x73 + DISC_ID[0] (0x55 / "U") => 0xC8
	loops 9 times and seemingly does nothing
	updates BUFFER[9] from 0xD3 to 0xD3 ^ XOR_TABLE_A[0] = 0x18
	updates BUFFER[9] from 0xD3 to 0xD3 + DISC_ID[9] (0x30 / "0") = 0x48
	updates BUFFER[18] from 0xCE to 0x05
	updates BUFFER[18] from 0x05 to 0x3A
	updates BUFFER[27] from ? to 0x50
	updates BUFFER[36] from 0x94 to 0xC4
	updates BUFFER[45] from 0x31 to 0x90
	updates BUFFER[54] from 0x11 to 0x41
	updates BUFFER[63] from 0xF7 to 0x30
	updates BUFFER[72] from 0x9F to 0xE3
	updates BUFFER[81] from 0xDA to 0x0A
	updates BUFFER[90] from 0x44 to 0x78
	updates BUFFER[99] from 0x70 to 0xBB
	updates BUFFER[108] from 0x1E to 0x4C
	updates BUFFER[117] from 0xA3 to 0xD8
	updates BUFFER[126] from 0x32 to 0x87
	is done while < 256
fifth pass
	compares to 0x140 for some reason
	computes overshoot 261-256 = 5
	reads BUFFER[261] (changed from 0xB6 to 0xAD)
	stores OVERSHOOT[5] = BUFFER[261] = 0xAD
	continues by increasing index_b from 0x105 to 0x106
	finds a pointer at 0x106
	increases limiting index from 0x100 to 0x13D
	subtracts 0x100 from 0x106 => 0x06
	reads dword at 0x106 (0x4071C0) and stores it at CALL_SCRATCH_SPACE[6]
	writes dword 0 to TABLE[6]
	writes dword 0 to BUFFER[6]
	increases 0x106 by 4 to 0x10A
	loops continue until next pointer without doing anything
	reads dword at 0x10A (4040C8) and stores it at CALL_SCRATCH_SPACE[12]
	loops a bunch
	updates BUFFER[0x117] (0xD6) ^ XOR_TABLE[0] (0xCB) => 0x1D => 0x4E
	this continues until counter is > 0x200
	finally increases index_a by one (when index a is 9, WPM is performed)

first pass (index 1):
	XOR_TABLE_A[1] = XOR_TABLE_A[1] (0xF5) ^ XOR_TABLE_B[1] (0x7C) = 0x89
	updates XOR_TABLE_A[1] from 0x89 to mixBytes(0x89, 0x00) = 0x89
	updates XOR_TABLE_A[1] from 0x89 to mixBytes(0x89, 0x01) = 0x13
	...
	=> 0x4C
second pass (index 1)
	updates XOR_tABLE_A[1] to 0x98
*/

function mixBytes(value: number, shift: number): number {
	value <<= (shift & 7);
	return ((value & 0xFF00) >>> 8) | (value & 0x00FF);
};

console.assert(mixBytes(0x98, 0x03) === 0xC4);

function mixBytesReverse(value: number, shift: number): number {
	return mixBytes(value, 8 - (shift & 7));
};

console.assert(mixBytesReverse(0x1E, 0x1F) === 0x3C);

// these are offsets of all "call absolute near" in .text+4096 (they are skipped during decryption)
// START OFFSET IS REFERENCED IN DECRYPT (CONSTANT_C)
const STATIC_DECRYPT_DATA = Uint8Array.from([
	// Offset 0x0001C140 to 0x0001C1D9
	0x00, 0x20, 0x00, 0x00, // (start offset)
	0x9C, 0x00, 0x00, 0x00, // (total size of record including this value and start offset, but checked for 0... so maybe not)
	0x06, 0x31, // the 3 is discarded so this becomes 0x106, which is first offset in area around oep where pointer should be restored after decryption
	0x0B, 0x31, // the 3 is discarded so this becomes 0x10B, which is second offset in area around oep where pointer should be restored after decryption
	0x28, 0x31,
	0x32, 0x31,
	0x40, 0x31,
	0x4B, 0x31,
	0x53, 0x31,
	0x88, 0x31,
	0x8D, 0x31,
	0x97, 0x31,
	0xB3, 0x31,
	0xD6, 0x31,
	0x0A, 0x32,
	0x26, 0x32,
	0x2F, 0x32,
	0x4C, 0x32,
	0x65, 0x32,
	0x74, 0x32,
	0x56, 0x33,
	0x5E, 0x33,
	0xB8, 0x33,
	0xC5, 0x33,
	0x68, 0x34,
	0x77, 0x34,
	0x8D, 0x34,
	0xBD, 0x35,
	0x77, 0x36,
	0x81, 0x37,
	0xC8, 0x37,
	0xE9, 0x37,
	0x00, 0x38,
	0x75, 0x38,
	0x3D, 0x3B,
	0x41, 0x3B,
	0x45, 0x3B,
	0x49, 0x3B,
	0x4D, 0x3B,
	0x51, 0x3B,
	0x55, 0x3B,
	0x59, 0x3B,
	0x39, 0x3C,
	0x40, 0x3C,
	0x51, 0x3C,
	0x57, 0x3C,
	0x65, 0x3C,
	0x6B, 0x3C,
	0x73, 0x3C,
	0x7B, 0x3C,
	0x83, 0x3C,
	0x95, 0x3C,
	0x9D, 0x3C,
	0xCA, 0x3C,
	0xE5, 0x3C,
	0xF5, 0x3C,
	0xFB, 0x3C,
	0x0A, 0x3D,
	0x10, 0x3D,
	0x17, 0x3D,
	0x20, 0x3D,
	0x27, 0x3D,
	0x2F, 0x3D,
	0x35, 0x3D,
	0x40, 0x3D,
	0x48, 0x3D,
	0x97, 0x3F,
	0xA5, 0x3F,
	0xAB, 0x3F,
	0xC5, 0x3F,
	0xCA, 0x3F,
	0xD9, 0x3F,
	0xDF, 0x3F,
	0xEF, 0x3F,
	0xFA, 0x3F,
	0x00, 0x00
]);

/*
b7 89 a1 23
4c 36 02 1f
FE 0D 9F 86
55 EB 81 23
C7 73 E0 23
8A 73 EB 2F
5A 37 82 0F
A1 F9 1D B1
*/

// not in exe, 0 until after .text+4096 decrypt
// at read 0x200b: 8c 6b d5 4f c4 a6 14 9c 83
// after decrypt: 0x8E, 0x67, 0x1E, 0x7E, 0x1C, 0x0E, 0x78, 0xB4, 0xFE (always same)
const XOR_TABLE_A: number[] = [/*
	0x8C, 0x6B, 0xD5, 0x4F, 0xC4, 0xA6, 0x14, 0x9C, 0x83, */
	0xFB, 0xd3, 0x74, 0x9c, 0x16, 0x48, 0xec, 0x50, 0xa6
];

// not in exe, 0 until after .text+4096 decrypt
// intermediate values before actually decrypting: 5E 66 82 05 AB 17 E7 AC 73
// intermediate 98 8D 15 B6 D3 6C 03 8E AB (after cd spins)
// at read 0x200b: 83 e2 2f fe 9e 03 b8 de cb
// after read 0x200b: same as above
const XOR_TABLE_B: number[] = [/*
	0x83, 0xE2, 0x2F, 0xFE, 0x9E, 0x03, 0xB8, 0xDE, 0xCB, */
	0xf4, 0x5a, 0x8e, 0x2d, 0x4c, 0xed, 0x40, 0x12, 0xee
];

// not in exe, 0 until after .text+4096 decrypt
// after cd spins: 00 01 00 05 00 02 06 02 04 (random)
// after cd spins: 04 01 04 05 00 05 05 04 00 (random
// buffer[4] changes to 14 or 1C or something
// buffer does not change again, write out of oep happens
const OFFSET_TABLE: number[] = [/*
	0x03, 0x04, 0x01, 0x02, 0x1C, 0x05, 0x03, 0x08, 0x02, */
	0x03, 0x02, 0x06, 0x03, 0x1d, 0x04, 0x03, 0x05, 0x03
];

const OEP: number[] = [
	// Offset 0x00013B99 to 0x00013B9C
	0x00, 0x21, 0x40, 0x00
];

// Read two 16 bit little endian numbers and sum them.
const ENCRYPTED_RANGE: number[] = [
	// Offset 0x0001C0FC to 0x0001C0FF
	0x00, 0x10, 0x00, 0x30
];

// Table becomes disc id like "UKD_NNNNNN.001". These are the bytes stored in exe, reverse xored (length 0x0E/14)
const DISC_ID_ENCRYPTED: number[] = [
	// Offset 0x0001C948 to 0x0001C955
	0x1E, 0x0F, 0x1B, 0x6A, 0x00, 0x01, 0x0D, 0x09, 0x00, 0x1E, 0x1E, 0x00,	0x01, 0x31
];

function decryptBackwardsXoredString(encrypted: Array<number>): Array<number> {
	let decrypted = encrypted.slice();
	for (let i = encrypted.length - 2; i >= 0; i--) {
		decrypted[i] = decrypted[i] ^ decrypted[i + 1];
	}
	return decrypted;
};

const DISC_ID_DECRYPTED = decryptBackwardsXoredString(DISC_ID_ENCRYPTED);

// unchanged after .text+0 decrypt
// becomes B7 0F 07 0C FE CB 96 9A EC 00 00 00 00 00 00 00 + C4 6D 3B 7B after .cms_t+2880 decrypt (static)
// unchanged after .cms_t+23034 decrypt
// changes a couple of times
// then cd spins
// changes to 07 F8 9B 72 D9 5D A5 73 BB before cdrom spins
// write index0: 0C, 06, C0, 0C, 81, 0C, 03, 0C, B9
// writes all bytes
// writes index0: 9 times
// writes all bytes
// times: 1
// becomes E2 F4 59 D1 D5 A4 B7 6C 8A 00 00 00 00 00 00 00 + C4 6D 3B 7B after .text+4096 decrypt
// copied into xor_table_a
const DECRYPT_TABLE_80: number[] = [
	// Offset 0x0001C980 to 0x0001C9CF
	0x3D, 0xF6, 0x8D, 0x7F, 0x0A, 0x5A, 0xBC, 0x2F, 0x6E, 0x7E, 0xA1, 0x54, 0xA0, 0xDF, 0x90, 0x21,
	0x88, 0x6B, 0x50, 0x41, 0xDA, 0xDD, 0x92, 0x9B, 0x1D, 0xE4, 0x59, 0xAE, 0xFE, 0x61, 0xC6, 0x0D,
	0xA6, 0x53, 0x06, 0x99, 0x8C, 0x53, 0xF8, 0xD3, 0xF1, 0x09, 0x00, 0xFF, 0x60, 0x66, 0x4A, 0x7F,
	0xA6, 0x31, 0xB8, 0x58, 0x94, 0x97, 0x5D, 0x8D, 0xAF, 0x32, 0xDF, 0xF6, 0xBE, 0x36, 0x60, 0x84,
	0xEE, 0x73, 0xFF, 0x54, 0xAF, 0x27, 0x04, 0xD1, 0xFB, 0x3B, 0xF8, 0xAE, 0x75, 0x57, 0x0E, 0x93
];

const VARIABLE_A: number[] = [
	0x1d
];

const VARIABLE_B: number[] = [
	0x1d
];

// PERMUTES INPUT
function permutateKey(xor_table_a: Array<number>, xor_table_b: Array<number>, offset_table: Array<number>, variable_a: Array<number>, variable_b: Array<number>): Array<number> {
	for (let key_index = 0; key_index < 9; key_index = key_index + 1) {
		xor_table_a[key_index] ^= xor_table_b[key_index];
		for (let key_permutation_index = 0; key_permutation_index < 9; key_permutation_index = key_permutation_index + 1) {
			if (key_permutation_index === 4) {
				variable_a[0] = (variable_a[0] - 0x15) & 0xFF;
				xor_table_a[key_index] = mixBytesReverse(xor_table_a[key_index], offset_table[key_permutation_index] + 0x03);
			} else {
				if (key_index === 0) {
					let one = offset_table[key_permutation_index] + key_permutation_index + variable_a[0];
					let two = (key_permutation_index * 0x1F) + 0x30;
					xor_table_a[key_index] = mixBytes(xor_table_a[key_index], one - two);
				} else {
					let one = offset_table[key_permutation_index] + key_permutation_index;
					xor_table_a[key_index] = mixBytes(xor_table_a[key_index], one);
				}
			}
		}
		xor_table_a[key_index] = (xor_table_a[key_index] + variable_a[0] - variable_b[0] + (key_index + 5) * 0x89) & 0xFF;
	}
	return xor_table_a;
};

// same variable seems to fix things
const DESCRAMBLED_KEY = permutateKey(XOR_TABLE_A, XOR_TABLE_B, OFFSET_TABLE, VARIABLE_A, VARIABLE_A);

console.assert(convertToHexStringArray(DESCRAMBLED_KEY).join(" ") === "CB 67 1E 7E 1C 0E 78 B4 FE"); // first byte is not quite right, should be 0x8E (which works for decryption)
/*
console.log(convertToHexStringArray(DESCRAMBLED_KEY)); */
DESCRAMBLED_KEY[0] = 0x8E;

function decryptTextCore(encrypted: Uint8Array, index_d: number, length: number, static_decrypt_data: Uint8Array, decrypted_disc_id: Array<number>, descrambled_key: Array<number>): Uint8Array {
let index_e = 0x100;
	let dw = new DataView(static_decrypt_data.buffer, static_decrypt_data.byteOffset);
	let decrypted = encrypted.slice();
	for (let index_a = 0; index_a < 9; index_a = index_a + 1) {
		let index_b = 0;
		let index_c = 0;
		while (index_b < index_d) {
			if (dw.getUint32(4, true) === 0 || index_b !== (dw.getUint16(4 + 4 + index_c * 2, true) & 0x0FFF)) {
				index_b += 1;
			} else {
				index_c += 1;
				index_b += 4;
			}
		}
		while (index_b < index_d + length) {
			if (dw.getUint32(4, true) === 0 || index_b !== (dw.getUint16(4 + 4 + index_c * 2, true) & 0x0FFF)) {
				if (index_b % 9 === index_a) {
					if (index_b - index_d >= index_e) {
						if (index_b - index_d < index_e + 0x40) {
							// Store byte in buffer one.
						}
					}
					decrypted[index_b - index_d] = decrypted[index_b - index_d] ^ descrambled_key[index_b % 9];
					decrypted[index_b - index_d] = decrypted[index_b - index_d] + decrypted_disc_id[index_b % decrypted_disc_id.length];
					if (index_b - index_d >= index_e) {
						if (index_b - index_d < index_e + 0x40) {
							// Store byte in buffer two.
						}
					}
				}
				index_b += 1;
			} else {
				if (index_b - index_d >= index_e) {
					if (index_b - index_d < index_e + 0x3D) {
						// Store dword in buffer one.
						// Store dword (0) in buffer three.
						// Store dword (0) in buffer two.
					}
				}
				index_c += 1;
				index_b += 4;
			}
		}
	}
	return decrypted;
};

function convertToHexStringArray(array: Array<number>): Array<string> {
	return array.map((number) => number.toString(16).padStart(2, "0").toUpperCase());
};

// works
function decrypt(encrypted: Uint8Array, disc_id_encrypted: Array<number>, offset: number, length: number): Uint8Array {
	let modulo = disc_id_encrypted.length;
	let decrypted = encrypted.slice();
	let register = 0; // should work as 8 bit unsigned
	for (let i = offset + length - 2, j = i % modulo; i >= offset; i = i - 1, j = j === 0 ? modulo - 1 : j - 1) {
		let encrypted_byte = encrypted[i];
		register = ((register >>> 0) << 8) | encrypted_byte;
		register = (register + disc_id_encrypted[j]) & 0xFFFF;
		let decrypted_byte = (register & 0xFF) ^ decrypted[i + 1];
		decrypted[i] = decrypted_byte;/*
		console.log({ i, m: j, e: encrypted_byte.toString(16).toUpperCase().padStart(2, "0"), d: decrypted_byte.toString(16).toUpperCase().padStart(2, "0") }); */
	}
	return decrypted;
};

// address is va 0x434604 - image_base 0x400000 => rva 0x34604 - va(.cms_d) 0x1E000 => .cms_d+0x16604
let SLOTS_IN_OBFUSCATION_AREA_MINUS_ONE = 0x1FD3; // 8148 - 1

// starts with FF FF FF FF 00 00 FF FF FF FF
// address is va 0x41F368 - image_base 0x400000 => rva 0x1F368 - va (.cms_d) 0x1E000 => .cms_d+0x1368
let CMS_D_OFFSET_TO_OBFUSCATION_AREA = 0x1368;

let CALL_SCRATCH_SPACE = Uint8Array.of(
	0x3C, 0x58, 0xC0, 0x85, 0x31, 0xB6, 0xC0, 0x71, 0x40, 0x00, 0x1D, 0xC8, 0x40, 0x40, 0x00, 0x48,
	0x73, 0xB9, 0xCC, 0xDE, 0xAA, 0x94, 0xCA, 0xD6, 0xB7, 0xAB, 0xC2, 0xBD, 0xC5, 0x36, 0x0C, 0xE1,
	0xAD, 0x41, 0x37, 0x27, 0x29, 0xB9, 0xD2, 0x7E, 0xE8, 0xF2, 0x41, 0x00, 0x81, 0x85, 0x54, 0xDC,
	0xEF, 0x1B, 0xF8, 0x9C, 0x40, 0x00, 0x5B, 0x67, 0x34, 0x18, 0x35, 0x49, 0xB7, 0xCE, 0x25, 0xC1
);

function decryptOperandAtAddress(address: number, cms_d: Uint8Array): number {
	let call_scratch_space_dw = new DataView(CALL_SCRATCH_SPACE.buffer);
	let buffer_64_byte_dw = new DataView(new Uint8Array(0x40).buffer);
	let disc_id_dw = new DataView(Uint8Array.from(DISC_ID_DECRYPTED).buffer);
	let xor_table_one_dw = new DataView(Uint8Array.from(XOR_TABLE_A).buffer);
	let dw = new DataView(cms_d.buffer, cms_d.byteOffset, cms_d.byteLength);
	let word_one = (address >>> 16) ^ (address & 0xFFFF);
	let byte_one = XOR_TABLE_A[(word_one & 0xFF) % 9];
	let word_two = word_one ^ (byte_one << 8);
	let byte_two = XOR_TABLE_A[(word_two >>> 8) % 9];
	let word = word_two ^ (byte_two << 0);
	let obfuscation_area_slot = ((word % SLOTS_IN_OBFUSCATION_AREA_MINUS_ONE) + 1);
	let obfuscation_area_offset = CMS_D_OFFSET_TO_OBFUSCATION_AREA + obfuscation_area_slot * 0xA;
	while (true) {
		if (obfuscation_area_slot === 0) {
			throw new Error(`Slot 0 should not be used!`);
		}
		let dword_one = dw.getUint32(obfuscation_area_offset, true);
		let key_one = (xor_table_one_dw.getUint32(dword_one % 4, true) << 4) >>> 0;
		let dword_two = dword_one ^ key_one;
		if (dword_two === address) {
			break;
		} else {
			// Bits 15 and 14 contain the number of times the decryption algorithm is run before overwriting the original operand.
			// Bits 13 to 0 contain next slot for mismatches.
			let flags = dw.getUint16(obfuscation_area_offset + 4, true);
			obfuscation_area_slot = (flags >>> 0) & 0x3FFF;
			obfuscation_area_offset = CMS_D_OFFSET_TO_OBFUSCATION_AREA + obfuscation_area_slot * 0xA;
		}
	}
	let value_to_decrypt = dw.getUint32(obfuscation_area_offset + 6, true);
	let nibbles = ((address & 0xFFFF) << 16) + (address & 0xFFFF);
	let key_two = xor_table_one_dw.getUint32(address % 4, true);
	nibbles ^= key_two;
	if ((value_to_decrypt + 1) % 0x29 === 0) {
		//throw new Error(`Unhandled branch 0x40F75C!`);
	}
	for (let nibble_index = 0, nibble_mask = 0xF, nibble_shift = 0; nibble_index < 8; nibble_index = nibble_index + 1, nibble_mask = (nibble_mask << 4) >>> 0, nibble_shift = nibble_shift + 4) {
		let nibble = (nibbles & nibble_mask) >>> nibble_shift;
		let function_index = nibble % 0xC;
		if (function_index === 0) {
			value_to_decrypt ^= 0xB37E;
		} else if (function_index === 1) {
			value_to_decrypt ^= disc_id_dw.getUint32(0, true);
		} else if (function_index === 2) {
			value_to_decrypt ^= 0x00000000;
		} else if (function_index === 3) {
			value_to_decrypt ^= 0x7B3B6DC4;
		} else if (function_index === 4) {
			value_to_decrypt -= 0xDCC0;
			value_to_decrypt >>>= 0;
		} else if (function_index === 5) {
			value_to_decrypt += 0x6761;
			value_to_decrypt >>>= 0;
		} else if (function_index === 6) {
			value_to_decrypt ^= 0xE89B;
		} else if (function_index === 7) {
			value_to_decrypt ^= 0x00003EE3;
		} else if (function_index === 8) {
			value_to_decrypt -= 0x00204261;
			value_to_decrypt >>>= 0;
		} else if (function_index === 9) {
			value_to_decrypt += 0x000000FD;
			value_to_decrypt >>>= 0;
		} else if (function_index === 0xA) {
			value_to_decrypt ^= call_scratch_space_dw.getUint32(address % 0x25, true);
		} else if (function_index === 0xB) {
			// four dword indices at 0x436940
			let index0 = 0;
			let index1 = 1;
			let index2 = 2;
			let index3 = 3;
			value_to_decrypt >>>= buffer_64_byte_dw.getUint32(index0 * 4, true) & 0xFF;
			value_to_decrypt += buffer_64_byte_dw.getUint32(index1 * 4, true);
			value_to_decrypt >>>= 0;
			value_to_decrypt >>>= buffer_64_byte_dw.getUint32(index2 * 4, true) & 0xFF;
			value_to_decrypt += buffer_64_byte_dw.getUint32(index3 * 4, true);
			value_to_decrypt >>>= 0;
		}
	}
	return value_to_decrypt;
};

/*
DC DC
77 AE 4 3
B4 1E 3 4
7F 67 2 6
E4 8F 1 12
8D 02 0 0		=> 04
EE EF 4 3		=> ED
2D C6 3 4		=> C4
BF 7F 2 6		=> 81
BA D1 1 12		=> 47

8F 5E 0 0		=> CA
7C 25 4 3		=> B9
78 61 3 4		=> C5
E9 8E 2 6		=> 32
85 17 1 12		=> C3
*/
function decryptSecuromCore_v3_17_0(encrypted: Uint8Array): Uint8Array {
	let decrypted = encrypted.slice();
	let offset = 2880;
	let length = 16086;
	for (let i = length - 2, o = offset + i; i >= 0; i = i - 1, o = o - 1) {
		let encrypted_byte = decrypted[o];
		let decrypted_byte = encrypted_byte ^ decrypted[o + 1];
		let add = (12 / (i % 5)) >>> 0; // Division by zero is handled in SEH, needs to be accounted for.
		decrypted_byte += add === 0 ? decrypted_byte : add;
		decrypted_byte &= 0xFF;
		decrypted[o] = decrypted_byte;/*
		console.log(encrypted_byte.toString(16).toUpperCase().padStart(2, "0"), decrypted_byte.toString(16).toUpperCase().padStart(2, "0"), i % 5, add); */
	}
	return decrypted;
};

let folder = "./private/d2/";
let exe = "Game.exe";
let section_names_to_keep = [
	".text",
	".rdata",
	".data",
	".rsrc"
];
let buffers: Array<Uint8Array> = [];
let file_array = Uint8Array.from(fs.readFileSync(folder + exe));
let file_buffer = file_array.buffer;
let dos_header = pe.parseDOSHeader(file_buffer);
let optional_header_offset = dos_header.new_exe_offset + 24;
let data_directories_offset = optional_header_offset + 96;
let file_header = pe.parsePEFileHeader(file_buffer.slice(dos_header.new_exe_offset, optional_header_offset));
let optional_header = pe.parsePEOptionalHeader(file_buffer.slice(optional_header_offset, optional_header_offset + file_header.size_of_optional_header));
let sections_offset = optional_header_offset + file_header.size_of_optional_header;
let sections: Array<pe.PESectionHeader> = [];
let offset = sections_offset;
for (let i = 0; i < file_header.number_of_sections; i++) {
	let section_header = pe.parsePESectionHeader(file_buffer.slice(offset, offset + 40)); offset += 40;
	sections.push(section_header);
}
let headers = file_array.slice(0, optional_header.size_of_headers);
let headers_dw = new DataView(headers.buffer);
headers.fill(0, sections_offset);
buffers.push(headers);
// step 1: Decrypt text segment.
{
	let section = sections.find((section) => section.name.toLowerCase() === ".text".toLowerCase());
	if (section == null) {
		throw new Error(`Expected a section!`);
	}
	let data = pe.getRawPESectionData(file_buffer, section);
	data = decrypt(data, DISC_ID_ENCRYPTED, 0, 16384);
	file_array.set(data, section.pointer_to_raw_data);
}
// step 2: Decrypt securom core part 1.
{
	let section = sections.find((section) => section.name.toLowerCase() === ".cms_t".toLowerCase());
	if (section == null) {
		throw new Error(`Expected a section!`);
	}
	let data = pe.getRawPESectionData(file_buffer, section);
	data = decryptSecuromCore_v3_17_0(data);
	file_array.set(data, section.pointer_to_raw_data);
}
// step 3: Decrypt securom core part 2.
{

}
// step 4: Decrypt text segment core.
{
	let section = sections.find((section) => section.name.toLowerCase() === ".text".toLowerCase());
	if (section == null) {
		throw new Error(`Expected a section!`);
	}
	let data = pe.getRawPESectionData(file_buffer, section);
	let encrypted_slice = data.subarray(4096, 4096 + 0x200);
	let decrypted_slice = decryptTextCore(encrypted_slice, 0, 0x200, STATIC_DECRYPT_DATA, DISC_ID_DECRYPTED, DESCRAMBLED_KEY);
	data.set(decrypted_slice, 4096);
	file_array.set(data, section.pointer_to_raw_data);
}
// step 5: Fix API calls.
{
	let section = sections.find((section) => section.name.toLowerCase() === ".text".toLowerCase());
	if (section == null) {
		throw new Error(`Expected a section!`);
	}
	let data = pe.getRawPESectionData(file_buffer, section);
	let dw = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let operand_addresses: Array<number> = [];
	for (let i = 2; i < data.length;) {
		if (data[i-2] === 0xFF && data[i-1] === 0x15) {
			operand_addresses.push(i);
			i += 4;
		} else {
			i += 1;
		}
	}
	let histogram = new Map<number, number>();
	for (let operand_address of operand_addresses) {
		let operand = dw.getUint32(operand_address, true);
		let operand_relative_to_image = operand - optional_header.image_base;
		let operand_section: pe.PESectionHeader = section;
		for (let section of sections) {
			if (operand_relative_to_image >= section.virtual_address && operand_relative_to_image < section.virtual_address + section.virtual_size) {
				operand_section = section;
			}
		}
		if (operand_section !== section) {
			// TODO: check for executability
			histogram.set(operand, (histogram.get(operand) ?? 0) + 1);
		}
	}
	let most_common_call = Array.from(histogram.entries()).sort((one, two) => one[1] - two[1]).map((entry) => entry[0]).pop();
	if (most_common_call == null) {
		throw new Error(`Expected a Securom API call address!`);
	}
	let cms_d_section = sections.find((section) => section.name === ".cms_d");
	if (cms_d_section == null) {
		throw new Error(`Expected a section!`);
	}
	let cms_d_data = pe.getRawPESectionData(file_buffer, cms_d_section);/*
console.assert(decryptOperandAtAddress(0x402128, cms_d_data) === 0x4070D8);
console.assert(decryptOperandAtAddress(0x402C39, cms_d_data) === 0x407108); */
	for (let operand_address of operand_addresses) {
		let operand = dw.getUint32(operand_address, true);
		if (operand !== most_common_call) {
			continue;
		} else {
			let va = operand_address + optional_header.image_base + section.virtual_address;
			let fixed_operand = decryptOperandAtAddress(va, cms_d_data);
			dw.setUint32(operand_address, fixed_operand, true);
			console.log(`Replacing bad operand at virtual address ${va.toString(16)}: ${operand.toString(16)} => ${fixed_operand.toString(16)}`);
		}
	}
	file_array.set(data, section.pointer_to_raw_data);
}
// write new executable
let next_pointer_to_raw_data = optional_header.size_of_headers;
let next_virtual_address = optional_header.size_of_headers;
for (let section_name of section_names_to_keep) {
	let section = sections.find((section) => section.name.toLowerCase() === section_name.toLowerCase());
	if (section == null) {
		throw new Error(`Expected a section with name "${section_name}"!`);
	}
	let data = pe.getRawPESectionData(file_buffer, section);
	if (section_name === ".rsrc") {
		data = pe.RSRC.rebase(data, next_virtual_address - section.virtual_address);
		headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.RESOURCE_TABLE * 8 + 0, next_virtual_address, true);
	}
	buffers.push(data);
	let encoded_section_header = pe.serializePESectionHeader({
		...section,
		pointer_to_raw_data: next_pointer_to_raw_data,
		virtual_address: next_virtual_address
	});
	headers.set(encoded_section_header, sections_offset); sections_offset += encoded_section_header.length;
	next_pointer_to_raw_data += section.size_of_raw_data;
	next_virtual_address += section.virtual_size;
	next_virtual_address = multipleOf(next_virtual_address, optional_header.section_alignment);
}
headers_dw.setUint16(dos_header.new_exe_offset + 6, section_names_to_keep.length, true); // update number_of_sections
headers_dw.setUint16(dos_header.new_exe_offset + 22, headers_dw.getUint16(dos_header.new_exe_offset + 22, true) | pe.PEFileHeaderCharacteristics.IMAGE_FILE_RELOCS_STRIPPED, true); // update characteristics
headers_dw.setUint32(optional_header_offset + 4, 24576, true); // update size_of_code
headers_dw.setUint32(optional_header_offset + 8, 24576, true); // update size_of_initialized_data
headers_dw.setUint32(optional_header_offset + 12, 0, true); // update size_of_ununitialized_data
headers_dw.setUint32(optional_header_offset + 16, 8448, true); // update address_of_entry_point
headers_dw.setUint32(optional_header_offset + 20, 4096, true); // update base_of_code
headers_dw.setUint32(optional_header_offset + 24, 28672, true); // update base_of_data
headers_dw.setUint32(optional_header_offset + 56, 52608, true); // update size_of_image
pe.PEOptionalHeaderDataDirectoryIndex.IMPORT_TABLE // 5x40b headers => 200b
pe.PEOptionalHeaderDataDirectoryIndex.IAT_TABLE // 444b  5xthunk_lists with zero termination
// TODO: Locate IAT.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.IMPORT_TABLE * 8 + 0, 30460, true); // Update virtual address.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.IMPORT_TABLE * 8 + 4, 200, true); // Update size.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.BASE_RELOCATION_TABLE * 8 + 0, 0, true); // Update virtual address.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.BASE_RELOCATION_TABLE * 8 + 4, 0, true); // Update size.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.IAT_TABLE * 8 + 0, 28672, true); // Update virtual address.
headers_dw.setUint32(data_directories_offset + pe.PEOptionalHeaderDataDirectoryIndex.IAT_TABLE * 8 + 4, 444, true); // Update size.

// section names .text, .data, .rsrc has 0x15 after name
let buffer = Chunk.concat(buffers);
fs.writeFileSync(folder + exe + ".stripped", buffer);
/*
console.log(DISC_ID_DECRYPTED.map((k) => String.fromCharCode(k)).join("")); */
