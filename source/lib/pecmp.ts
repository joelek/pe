import * as fs from "fs";
import * as pe from "./pe";

let one = process.argv[2];

let one_file_array = Uint8Array.from(fs.readFileSync(one));
let one_file_buffer = one_file_array.buffer;
let one_dos_header = pe.parseDOSHeader(one_file_buffer);
let one_file_header = pe.parsePEFileHeader(one_file_buffer.slice(one_dos_header.new_exe_offset, one_dos_header.new_exe_offset + 24));
let one_optional_header = pe.parsePEOptionalHeader(one_file_buffer.slice(one_dos_header.new_exe_offset + 24, one_dos_header.new_exe_offset + 24 + one_file_header.size_of_optional_header));
let one_sections_offset = one_dos_header.new_exe_offset + 24 + one_file_header.size_of_optional_header;
let one_section_headers: Array<pe.PESectionHeader> = [];
for (let i = 0; i < one_file_header.number_of_sections; i++) {
	let section_header = pe.parsePESectionHeader(one_file_buffer.slice(one_sections_offset, one_sections_offset + 40)); one_sections_offset += 40;
	one_section_headers.push(section_header);
}

let two = process.argv[3];

let two_file_array = Uint8Array.from(fs.readFileSync(two));
let two_file_buffer = two_file_array.buffer;
let two_dos_header = pe.parseDOSHeader(two_file_buffer);
let two_file_header = pe.parsePEFileHeader(two_file_buffer.slice(two_dos_header.new_exe_offset, two_dos_header.new_exe_offset + 24));
let two_optional_header = pe.parsePEOptionalHeader(two_file_buffer.slice(two_dos_header.new_exe_offset + 24, two_dos_header.new_exe_offset + 24 + two_file_header.size_of_optional_header));
let two_sections_offset = two_dos_header.new_exe_offset + 24 + two_file_header.size_of_optional_header;
let two_section_headers: Array<pe.PESectionHeader> = [];
for (let i = 0; i < two_file_header.number_of_sections; i++) {
	let section_header = pe.parsePESectionHeader(two_file_buffer.slice(two_sections_offset, two_sections_offset + 40)); two_sections_offset += 40;
	two_section_headers.push(section_header);
}


if (one_file_array.length !== two_file_array.length) {
	console.log("!");
}
for (let i = 0; i < one_file_array.length; i++) {
	if (one_file_array[i] !== two_file_array[i]) {
console.log(`Differs at ${i}: ${one_file_array[i].toString(16)}, ${two_file_array[i].toString(16)}`);
	}
}


for (let i = 0; i < Math.min(one_section_headers.length, two_section_headers.length); i++) {
	let one_section_header = one_section_headers[i];
	let one_data = pe.getRawPESectionData(one_file_buffer, one_section_header);
	let two_section_header = two_section_headers[i];
	let two_data = pe.getRawPESectionData(two_file_buffer, two_section_header);
	console.log(`Checking section "${one_section_header.name}" against "${two_section_header.name}"...`);
	console.log(`Checking ${Math.min(one_data.length, two_data.length)} bytes...`);
	if (one_section_header.name === ".text" && two_section_header.name === ".text") {
		let first_diff: number | undefined;
		for (let j = 0; j < Math.min(one_data.length, two_data.length); j++) {
			if (one_data[j] !== two_data[j]) {
				if (one_data[j-2] === 0xFF && one_data[j-1] === 0x15) {
					let k = j - 0;
					let one_arg = (one_data[k+3] << 24) | (one_data[k+2] << 16) | (one_data[k+1] << 8) | (one_data[k+0] << 0);
					let two_arg = (two_data[k+3] << 24) | (two_data[k+2] << 16) | (two_data[k+1] << 8) | (two_data[k+0] << 0);
					one_arg -= two_optional_header.image_base;
					two_arg -= two_optional_header.image_base;
					console.log(`Different FF 15 call at offset ${k.toString(10).padStart(8, "0")}: ${one_arg.toString(10).padStart(8, "0")} vs ${two_arg.toString(10).padStart(8, "0")}`);
					j += 4;
				} else if (one_data[j-3] === 0xFF && one_data[j-2] === 0x15) {
					let k = j - 1;
					let one_arg = (one_data[k+3] << 24) | (one_data[k+2] << 16) | (one_data[k+1] << 8) | (one_data[k+0] << 0);
					let two_arg = (two_data[k+3] << 24) | (two_data[k+2] << 16) | (two_data[k+1] << 8) | (two_data[k+0] << 0);
					one_arg -= two_optional_header.image_base;
					two_arg -= two_optional_header.image_base;
					console.log(`Different FF 15 call at offset ${k.toString(10).padStart(8, "0")}: ${one_arg.toString(10).padStart(8, "0")} vs ${two_arg.toString(10).padStart(8, "0")}`);
					j += 3;
				} else if (one_data[j-4] === 0xFF && one_data[j-3] === 0x15) {
					let k = j - 2;
					let one_arg = (one_data[k+3] << 24) | (one_data[k+2] << 16) | (one_data[k+1] << 8) | (one_data[k+0] << 0);
					let two_arg = (two_data[k+3] << 24) | (two_data[k+2] << 16) | (two_data[k+1] << 8) | (two_data[k+0] << 0);
					one_arg -= two_optional_header.image_base;
					two_arg -= two_optional_header.image_base;
					console.log(`Different FF 15 call at offset ${k.toString(10).padStart(8, "0")}: ${one_arg.toString(10).padStart(8, "0")} vs ${two_arg.toString(10).padStart(8, "0")}`);
					j += 2;
				} else if (one_data[j-5] === 0xFF && one_data[j-4] === 0x15) {
					let k = j - 3;
					let one_arg = (one_data[k+3] << 24) | (one_data[k+2] << 16) | (one_data[k+1] << 8) | (one_data[k+0] << 0);
					let two_arg = (two_data[k+3] << 24) | (two_data[k+2] << 16) | (two_data[k+1] << 8) | (two_data[k+0] << 0);
					one_arg -= two_optional_header.image_base;
					two_arg -= two_optional_header.image_base;
					console.log(`Different FF 15 call at offset ${k.toString(10).padStart(8, "0")}: ${one_arg.toString(10).padStart(8, "0")} vs ${two_arg.toString(10).padStart(8, "0")}`);
					j += 1;
				} else {
					if (first_diff == null) {
						first_diff = j;
					}
				}
			} else {
				if (first_diff != null) {
					let one = Array.from(one_data.subarray(first_diff, j)).map((k) => k.toString(16).padStart(2, "0")).join(" ");
					let two = Array.from(two_data.subarray(first_diff, j)).map((k) => k.toString(16).padStart(2, "0")).join(" ");
					console.log(`Different bytes at offset ${first_diff.toString(10).padStart(8, "0")} to ${(j-1).toString(10).padStart(8, "0")}`);
					console.log(`\t${one}`);
					console.log(`\t${two}`);
					first_diff = undefined;
				}
			}
		}
		if (first_diff != null) {
			let one = Array.from(one_data.subarray(first_diff)).map((k) => k.toString(16).padStart(2, "0")).join(" ");
			let two = Array.from(two_data.subarray(first_diff)).map((k) => k.toString(16).padStart(2, "0")).join(" ");
			console.log(`Different bytes at offset ${first_diff.toString(10).padStart(8, "0")}`);
			console.log(`\t${one}!`);
			console.log(`\t${two}!`);
			first_diff = undefined;
		}
	} else {
		for (let j = 0; j < Math.min(one_data.length, two_data.length); j++) {
			if (one_data[j] !== two_data[j]) {
				console.log(`Different byte at offset ${j.toString(10).padStart(8, "0")}: ${one_data[j].toString(16).padStart(2, "0")} vs ${two_data[j].toString(16).padStart(2, "0")}!`);
			}
		}
	}
}
