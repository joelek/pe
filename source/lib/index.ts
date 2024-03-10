import { Chunk } from "@joelek/ts-stdlib/dist/lib/data/chunk";
import * as pe from "./pe";
import * as fs from "fs";
import * as tea from "./tea";


























let empires2_missing = [
	688473632,
	688471524
];

let h3blade_missing = [
	2312225663,
	2312226525
];

let h3sod_missing = [
	1899535641,
	1899536935
];

let nox_missing = [
	1630982900,
	1630984094
];

let sims_missing = [
	861790573,
	861792625
];

let cncts_missing: Array<number> = [];

function getMissingFunctions(key: number): Array<number> {
	if (key == 0x292DF9F0) {
		return empires2_missing;
	}
	if (key === 0x563B3039) {
		return cncts_missing;
	}
	if (key === 0x09F5B90B) {
		return h3blade_missing;
	}
	if (key === 0x711D791B) {
		return h3sod_missing;
	}
	if (key === 0x61203264) {
		return nox_missing;
	}
	if (key === 0x33438CC7) {
		return sims_missing;
	}
	return [];
};

function getKeyValue(e0: number, e1: number): number {
	if (e0 === 0x4D0E7E3C && e1 === 0x533EF854) {
		return 0x292DF9F0;
	}
	if (e0 === 0x0AEDE6A7 && e1 === 0x9265E001) {
		return 0x563B3039;
	}
	if (e0 === 0xA38A644E && e1 === 0x98819DDF) {
		return 0x09F5B90B;
	}
	if (e0 === 0x13D8DAE8 && e1 === 0x95E31D5B) {
		return 0x711D791B;
	}
	if (e0 === 0xE9424584 && e1 === 0x49708EA1) {
		return 0x61203264;
	}
	if (e0 === 0x8A1AC7B2 && e1 === 0xF6448024) {
		return 0x33438CC7;
	}
	process.stderr.write(`Key not found in database. Brute-force necessary.\n`);
	return bruteForceKey(e0, e1);
};

function getSafediscVersion(key: number): string {
	if (key === 0x563B3039) {
		return "1.11.0";
	}
	if (key === 0x292DF9F0) {
		return "1.30.10"
	}
	if (key === 0x09F5B90B) {
		return "1.30.10";
	}
	if (key === 0x711D791B) {
		return "1.41.0";
	}
	if (key === 0x61203264) {
		return "1.40.4";
	}
	if (key === 0x33438CC7) {
		return "1.40.4";
	}
	throw new Error(`Expected a Safedisc version!`);
};

function bruteForceKey(t0: number, t1: number): number {
	let last_percentage = "0";
	for (let i = 0, l = 2 ** 32; i < l; i++) {
		let { e0, e1 } = tea.encrypt_chunk(0, 0, i, i, i, i);
		if (e0 === t0 && e1 === t1) {
			process.stderr.write(`Key successfully brute-forced! ${i.toString(16).padStart(8, "0").toUpperCase()}\n`);
			return i;
		}
		let new_percentage = (i / l * 100).toFixed(0);
		if (new_percentage !== last_percentage) {
			process.stderr.write(`Tested ${new_percentage}% of all possible keys...\n`);
			last_percentage = new_percentage;
		}
	}
	throw new Error(`Expected a key to be successfully brute-forced!`);
};

function getBruteForceCandidate(buffer: ArrayBuffer, section_headers: Array<pe.PESectionHeader>): { e0: number; e1: number; } {
	let section_header = section_headers.find((section_header) => section_header.name.toLowerCase() === ".data");
	if (section_header == null) {
		throw new Error(`Expected a ".data" section!`);
	}
	let data = pe.getRawPESectionData(buffer, section_header);
	let histogram = new Map<string, number>();
	for (let s = 0, e = s + 8, l = data.length - 16; s < l; s = e, e += 8) {
		let string =  Chunk.toString(data.subarray(s, e), "hex");
		histogram.set(string, (histogram.get(string) ?? 0) + 1);
	}
	let entry = Array.from(histogram.entries()).sort((one, two) => one[1] - two[1]).pop();
	if (entry == null) {
		throw new Error(`Expected a histogram entry!`);
	}
	let [string, frequency] = entry;
	if (frequency < 2) {
		throw new Error(`Expected an 8 byte chunk with a frequency of at least 2!`);
	}
	let chunk = Chunk.fromString(string, "hex");
	let view = new DataView(chunk.buffer);
	let e0 = view.getUint32(0, true);
	let e1 = view.getUint32(4, true);
	process.stderr.write(e0.toString(16).padStart(8, "0").toUpperCase() + "\n")
	process.stderr.write(e1.toString(16).padStart(8, "0").toUpperCase() + "\n");
	return {
		e0,
		e1
	};
}

function decryptFunctionName(offset: number, dw: DataView, thunk_key: number): void {
	let length = dw.getUint8(offset);
	dw.setUint16(offset, 0, true);
	let last_encrypted_byte = ((thunk_key >>> 24) ^ 0xAB) >>> 0;
	for (let o = offset + 2, e = o + length; o < e; o += 1) {
		let encrypted_byte = dw.getUint8(o);
		let decrypted_byte = encrypted_byte ^ last_encrypted_byte;
		dw.setUint8(o, decrypted_byte);
		last_encrypted_byte = encrypted_byte;
	}
};

// raw decimal offset 00010512 in dplayerx.dll
function createJumpTable(length: number, key: number): { table: number[]; inverse_table: number[]; } {
	let shift_one = 0;
	for (let l = length; l > 0; l >>>= 1) {
		shift_one += 1;
	}
	let table = new Array(length).fill(0).map((value, index) => index);
	let shift_two = (32 - shift_one) >>> 0;
	for (let i = 0; i < length; i++) {
		key = Math.imul(key, 0x35E85A6D) >>> 0;
		key = (key + 0x361962E9) >>> 0;
		let target_index = key;
		target_index = (target_index >>> shift_one) >>> 0;
		target_index = Math.imul(target_index, length) >>> 0;
		target_index = (target_index >>> shift_two) >>> 0;
		if (target_index !== i) {
			let a = table[i];
			let b = table[target_index];
			table[i] = b;
			table[target_index] = a;
		}
	}
	let inverse_table = new Array(length).fill(0).map((value, index) => index);
	for (let i = 0; i < length; i++) {
		inverse_table[table[i]] = i;
	}
	return {
		table,
		inverse_table
	};
};

function modulo(a: number, b: number): number {
	return ((a % b) + b) % b;
};
























let folder = `./private/d2/`;
let icd = `Game.exe`;
let file_array = Uint8Array.from(fs.readFileSync(folder + icd));
let file_buffer = file_array.buffer;
let dos_header = pe.parseDOSHeader(file_buffer);
let file_header = pe.parsePEFileHeader(file_buffer.slice(dos_header.new_exe_offset, dos_header.new_exe_offset + 24));
let optional_header = pe.parsePEOptionalHeader(file_buffer.slice(dos_header.new_exe_offset + 24, dos_header.new_exe_offset + 24 + file_header.size_of_optional_header));
let sections_offset = dos_header.new_exe_offset + 24 + file_header.size_of_optional_header;
let section_headers: Array<pe.PESectionHeader> = [];
console.log(JSON.stringify({ dos_header, file_header, optional_header }, null, 4));
for (let i = 0; i < file_header.number_of_sections; i++) {
	let section_header = pe.parsePESectionHeader(file_buffer.slice(sections_offset, sections_offset + 40));
	section_headers.push(section_header); sections_offset += 40;
}
console.log(JSON.stringify({ section_headers }, null, 4));
process.stdout.write(`Offset after section headers is ${sections_offset}.\n`);
let section_headers_copy = section_headers.slice().sort((one, two) => one.pointer_to_raw_data - two.pointer_to_raw_data);
{
	let length = section_headers_copy[0].pointer_to_raw_data - sections_offset;
	if (length !== 0) {
		console.log(`Found ${length} unspecified bytes at offset ${sections_offset}, before section data (this is normal and part of section data alignment).`);
		sections_offset += length;
	}
}
for (let section of section_headers_copy) {
	let length = section.pointer_to_raw_data - sections_offset;
	if (length !== 0) {
		console.log(`Found ${length} unspecified bytes at offset ${sections_offset}, just before section "${section.name}"!`);
		sections_offset += length;
	}
	let unused = section.size_of_raw_data - section.virtual_size;
	if (unused > 0) {
		console.log(`Section "${section.name}" has ${unused} unused bytes at offset ${sections_offset + section.virtual_size}.`);
	}
	sections_offset += section.size_of_raw_data;
}
{
	let length = file_array.length - sections_offset;
	if (length !== 0) {
		console.log(`Found ${length} unspecified bytes at offset ${sections_offset}, after section data!`);
	}
}


let { e0, e1 } = getBruteForceCandidate(file_buffer, section_headers);
let key_value = getKeyValue(e0, e1);
let safedisc_version = getSafediscVersion(key_value);
process.stderr.write(`Using section key: ${key_value.toString(16).padStart(8, "0").toUpperCase()}\n`);
let thunk_key = key_value & 0xF0000000 ? key_value : key_value + 0x80000000;
process.stderr.write(`Using thunk key: ${thunk_key.toString(16).padStart(8, "0").toUpperCase()}\n`);
let key = new ArrayBuffer(16);
let key_dw = new DataView(key);
key_dw.setUint32(0, key_value, true);
key_dw.setUint32(4, key_value, true);
key_dw.setUint32(8, key_value, true);
key_dw.setUint32(12, key_value, true);
if (fs.existsSync(folder + `sections/`)) {
	fs.rmSync(folder + `sections/`, { recursive: true });
}
fs.mkdirSync(folder + `sections/`, { recursive: true });
for (let section_header of section_headers) {
	let data = pe.getRawPESectionData(file_buffer, section_header);
	fs.writeFileSync(folder + `sections/${section_header.name}_encrypted`, data);
	let encrypted_data = data.slice(0, Math.min(section_header.virtual_size, section_header.size_of_raw_data));
	if (![".rdata", ".rsrc"].includes(section_header.name)) {
		process.stdout.write(`Decrypting section ${section_header.name} using key ${key_value}\n`);
		let decrypted_data = tea.decrypt(encrypted_data.buffer, key);
		new Uint8Array(file_buffer).set(decrypted_data, section_header.pointer_to_raw_data);
		data.set(decrypted_data);
	}
	fs.writeFileSync(folder + `sections/${section_header.name}_decrypted`, data);
}

let { section_header, offset } = pe.getSectionHeaderContainingImportTable(optional_header, section_headers);
let { import_directory_table } = pe.readPEImportDirectoryTable(file_buffer, section_header, offset);
let import_section_array = pe.getRawPESectionData(file_buffer, section_header);
let import_section_buffer = import_section_array.buffer;
let import_section_data_view = new DataView(import_section_buffer);
console.log(JSON.stringify(import_directory_table, null, 4))
let missing_functions = getMissingFunctions(key_value);
console.log("missing functions", missing_functions);
let kernel32 = import_directory_table.find((table) => table.name.toLowerCase() === "kernel32.dll");
if (kernel32 == null) {
	throw new Error(`Expected import table for "kernel32.dll"!`);
}
let kernel32_original_first_thunk_offset = kernel32.original_first_thunk_rva - section_header.virtual_address;
let kernel32_first_thunk_offset = kernel32.first_thunk_rva - section_header.virtual_address;
{
	let thunks: Array<number> = [];
	if (missing_functions.length === 2) {
		if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
			import_section_data_view.setUint32(kernel32_original_first_thunk_offset, missing_functions[0], true);
			import_section_data_view.setUint32(kernel32_first_thunk_offset, missing_functions[0], true);
		} else {
			import_section_data_view.setBigUint64(kernel32_original_first_thunk_offset, BigInt(missing_functions[0]), true);
			import_section_data_view.setBigUint64(kernel32_first_thunk_offset, BigInt(missing_functions[0]), true);
		}
		while (true) {
			if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
				let thunk = import_section_data_view.getUint32(kernel32_original_first_thunk_offset + thunks.length * 4, true);
				if (thunk === 0) {
					break;
				}
				thunk ^= thunk_key;
				import_section_data_view.setUint32(kernel32_original_first_thunk_offset + thunks.length * 4, thunk, true);
				import_section_data_view.setUint32(kernel32_first_thunk_offset + thunks.length * 4, thunk, true);
				thunks.push(thunk);
				decryptFunctionName(thunk - section_header.virtual_address, import_section_data_view, thunk_key);
			} else {
				let thunk = Number(import_section_data_view.getBigUint64(kernel32_original_first_thunk_offset + thunks.length * 8, true));
				if (thunk === 0) {
					break;
				}
				thunk ^= thunk_key;
				import_section_data_view.setBigUint64(kernel32_original_first_thunk_offset + thunks.length * 8, BigInt(thunk), true);
				import_section_data_view.setBigUint64(kernel32_first_thunk_offset + thunks.length * 8, BigInt(thunk), true);
				thunks.push(thunk);
				decryptFunctionName(thunk - section_header.virtual_address, import_section_data_view, thunk_key);
			}
		}
	} else {
		thunks = pe.readPEImportDirectoryTableThunks(kernel32_original_first_thunk_offset, import_section_data_view, optional_header);
	}
	let correct_thunks: Array<number> = [];
	let { table, inverse_table } = createJumpTable(thunks.length, thunk_key);
	for (let i = 0, l = thunks.length; i < l; i++) {
		let correct_thunk = thunks[inverse_table[i]];
		correct_thunks.push(correct_thunk);
		if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
			import_section_data_view.setUint32(kernel32_original_first_thunk_offset + i * 4, correct_thunk, true);
			import_section_data_view.setUint32(kernel32_first_thunk_offset + i * 4, correct_thunk, true);
		} else {
			import_section_data_view.setBigUint64(kernel32_original_first_thunk_offset + i * 8, BigInt(correct_thunk), true);
			import_section_data_view.setBigUint64(kernel32_first_thunk_offset + i * 8, BigInt(correct_thunk), true);
		}
	}
	file_array.set(import_section_array, section_header.pointer_to_raw_data);
	console.log(JSON.stringify(pe.readPEImportDirectoryTableThunkEntries(file_buffer, optional_header, kernel32, section_header), null, 4));
}
let user32 = import_directory_table.find((table) => table.name.toLowerCase() === "user32.dll");
if (user32 == null) {
	throw new Error(`Expected import table for "user32.dll"!`);
}
let user32_original_first_thunk_offset = user32.original_first_thunk_rva - section_header.virtual_address;
let user32_first_thunk_offset = user32.first_thunk_rva - section_header.virtual_address;
{
	let thunks: Array<number> = [];
	if (missing_functions.length === 2) {
		if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
			import_section_data_view.setUint32(user32_original_first_thunk_offset, missing_functions[1], true);
			import_section_data_view.setUint32(user32_first_thunk_offset, missing_functions[1], true);
		} else {
			import_section_data_view.setBigUint64(user32_original_first_thunk_offset, BigInt(missing_functions[1]), true);
			import_section_data_view.setBigUint64(user32_first_thunk_offset, BigInt(missing_functions[1]), true);
		}
		while (true) {
			if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
				let thunk = import_section_data_view.getUint32(user32_original_first_thunk_offset + thunks.length * 4, true);
				if (thunk === 0) {
					break;
				}
				thunk ^= thunk_key;
				import_section_data_view.setUint32(user32_original_first_thunk_offset + thunks.length * 4, thunk ^ thunk_key, true);
				import_section_data_view.setUint32(user32_first_thunk_offset + thunks.length * 4, thunk ^ thunk_key, true);
				thunks.push(thunk);
				decryptFunctionName(thunk - section_header.virtual_address, import_section_data_view, thunk_key);
			} else {
				let thunk = Number(import_section_data_view.getBigUint64(user32_original_first_thunk_offset + thunks.length * 8, true));
				if (thunk === 0) {
					break;
				}
				thunk ^= thunk_key;
				import_section_data_view.setBigUint64(user32_original_first_thunk_offset + thunks.length * 8, BigInt(thunk), true);
				import_section_data_view.setBigUint64(user32_first_thunk_offset + thunks.length * 8, BigInt(thunk), true);
				thunks.push(thunk);
				decryptFunctionName(thunk - section_header.virtual_address, import_section_data_view, thunk_key);
			}
		}
	} else {
		thunks = pe.readPEImportDirectoryTableThunks(user32_original_first_thunk_offset, import_section_data_view, optional_header);
	}
	let { table, inverse_table } = createJumpTable(thunks.length, thunk_key);
	let correct_thunks: Array<number> = [];
	for (let i = 0, l = thunks.length; i < l; i++) {
		let correct_thunk = thunks[inverse_table[i]];
		correct_thunks.push(correct_thunk);
		if (optional_header.type === pe.PEOptionalHeaderType.PE32) {
			import_section_data_view.setUint32(user32_original_first_thunk_offset + i * 4, correct_thunk, true);
			import_section_data_view.setUint32(user32_first_thunk_offset + i * 4, correct_thunk, true);
		} else {
			import_section_data_view.setBigUint64(user32_original_first_thunk_offset + i * 8, BigInt(correct_thunk), true);
			import_section_data_view.setBigUint64(user32_first_thunk_offset + i * 8, BigInt(correct_thunk), true);
		}
	}
	file_array.set(import_section_array, section_header.pointer_to_raw_data);
	console.log(JSON.stringify(pe.readPEImportDirectoryTableThunkEntries(file_buffer, optional_header, user32, section_header), null, 4));
}
if (safedisc_version === "1.40.4" || safedisc_version === "1.41.0") {
	let kernel32_thunks = pe.readPEImportDirectoryTableThunks(kernel32_first_thunk_offset, import_section_data_view, optional_header);
	let user32_thunks = pe.readPEImportDirectoryTableThunks(user32_first_thunk_offset, import_section_data_view, optional_header);
	let text_section = section_headers.find((section_header) => section_header.name === ".text");
	if (text_section == null) {
		throw new Error(`Expected a ".text" section!`);
	}
	let text_array = pe.getRawPESectionData(file_buffer, text_section);
	let text_buffer = text_array.buffer;
	let text_view = new DataView(text_buffer);
	// Find all call dword ptr m32
	for (let i = 0, l = text_array.length - 6; i < l; i += 1) {
		if (text_array[i+0] !== 0xFF) {
			continue;
		}
		if (text_array[i+1] !== 0x15) {
			continue;
		}
		let adjusted_i = i + key_value;
		if (safedisc_version === "1.40.4") {
			let is_encrypted = (adjusted_i % 3) === 1;
			if (!is_encrypted) {
				i += 5;
				continue;
			}
		} else if (safedisc_version === "1.41.0") {
			let is_encrypted = (adjusted_i % 4) !== 3;
			if (!is_encrypted) {
				i += 5;
				continue;
			}
		}
		let bad_operand = text_view.getUint32(i+2, true);
		let bad_operand_relative_to_image_base = bad_operand - optional_header.image_base;
		if (bad_operand_relative_to_image_base >= kernel32.first_thunk_rva && bad_operand_relative_to_image_base < kernel32.first_thunk_rva + kernel32_thunks.length * 4) {
			let bad_index = (bad_operand_relative_to_image_base - kernel32.first_thunk_rva) / 4;
			let good_index = modulo((bad_index - modulo(adjusted_i, kernel32_thunks.length)), kernel32_thunks.length);
			let good_operand = optional_header.image_base + kernel32.first_thunk_rva + good_index * 4;
			process.stderr.write(`Replacing bad operand at .text+${i+2}, ${bad_operand} with ${good_operand}.\n`);
			text_view.setUint32(i+2, good_operand, true);
		} else if (bad_operand_relative_to_image_base >= user32.first_thunk_rva && bad_operand_relative_to_image_base < user32.first_thunk_rva + user32_thunks.length * 4) {
			let bad_index = (bad_operand_relative_to_image_base - user32.first_thunk_rva) / 4;
			let good_index = modulo((bad_index - modulo(adjusted_i, user32_thunks.length)), user32_thunks.length);
			let good_operand = optional_header.image_base + user32.first_thunk_rva + good_index * 4;
			process.stderr.write(`Replacing bad operand at .text+${i+2}, ${bad_operand} with ${good_operand}.\n`);
			text_view.setUint32(i+2, good_operand, true);
		}
		i += 5;
	}
	file_array.set(text_array, text_section.pointer_to_raw_data);
}
fs.writeFileSync(folder + icd + ".exe", file_array);
