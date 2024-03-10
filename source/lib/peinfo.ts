import { Chunk } from "@joelek/ts-stdlib/dist/lib/data/chunk";
import * as pe from "./pe";
import * as fs from "fs";
import * as path from "path";

let target = process.argv[2];
let directory = path.dirname(target) + "/";
let filename = path.basename(target);
let file_array = Uint8Array.from(fs.readFileSync(target));
let file_buffer = file_array.buffer;
let dos_header = pe.parseDOSHeader(file_buffer);
console.log(JSON.stringify({ dos_header }, null, 4));

let file_header = pe.parsePEFileHeader(file_buffer.slice(dos_header.new_exe_offset, dos_header.new_exe_offset + 24));
console.log(JSON.stringify({ file_header }, null, 4));
let optional_header = pe.parsePEOptionalHeader(file_buffer.slice(dos_header.new_exe_offset + 24, dos_header.new_exe_offset + 24 + file_header.size_of_optional_header));
console.log(JSON.stringify({ optional_header }, null, 4));
let sections_offset = dos_header.new_exe_offset + 24 + file_header.size_of_optional_header;
let section_headers: Array<pe.PESectionHeader> = [];
for (let i = 0; i < file_header.number_of_sections; i++) {
	let section_header = pe.parsePESectionHeader(file_buffer.slice(sections_offset, sections_offset + 40)); sections_offset += 40;
	section_headers.push(section_header);
	console.log(JSON.stringify({ section_header }, null, 4));
}
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
if (fs.existsSync(directory + `sections/`)) {
	fs.rmSync(directory + `sections/`, { recursive: true });
}
fs.mkdirSync(directory + `sections/`, { recursive: true });
for (let section_header of section_headers) {
	let data = pe.getRawPESectionData(file_buffer, section_header);
	fs.writeFileSync(directory + `sections/${section_header.name}`, data);
}

/* let { section_header, offset } = pe.getSectionHeaderContainingImportTable(optional_header, section_headers);
let { import_directory_table } = pe.readPEImportDirectoryTable(file_buffer, section_header, offset);
let import_section_array = pe.getRawPESectionData(file_buffer, section_header);
let import_section_buffer = import_section_array.buffer;
let import_section_data_view = new DataView(import_section_buffer);
console.log(JSON.stringify(import_directory_table, null, 4))
let kernel32 = import_directory_table.find((table) => table.name.toLowerCase() === "kernel32.dll");
if (kernel32 == null) {
	throw new Error(`Expected import table for "kernel32.dll"!`);
}
let kernel32_original_first_thunk_offset = kernel32.original_first_thunk_rva - section_header.virtual_address;
let kernel32_first_thunk_offset = kernel32.first_thunk_rva - section_header.virtual_address;
let kernel32_thunks = pe.readPEImportDirectoryTableThunks(kernel32_original_first_thunk_offset, import_section_data_view, optional_header);
let kernel32_thunks2 = pe.readPEImportDirectoryTableThunkEntries(file_buffer, optional_header, kernel32, section_header);
let user32 = import_directory_table.find((table) => table.name.toLowerCase() === "user32.dll");
if (user32 == null) {
	throw new Error(`Expected import table for "user32.dll"!`);
}
let user32_original_first_thunk_offset = user32.original_first_thunk_rva - section_header.virtual_address;
let user32_first_thunk_offset = user32.first_thunk_rva - section_header.virtual_address;
let user32_thunks = pe.readPEImportDirectoryTableThunks(user32_original_first_thunk_offset, import_section_data_view, optional_header);
let user32_thunks2 = pe.readPEImportDirectoryTableThunkEntries(file_buffer, optional_header, user32, section_header);
let entry_point = pe.getSectionHeaderContainingEntryPoint(optional_header, section_headers);
 */
