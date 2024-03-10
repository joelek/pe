import { Chunk } from "@joelek/ts-stdlib/dist/lib/data/chunk";

export function zeroTerminate(string: Uint8Array, length: number): Uint8Array {
	let buffer = new Uint8Array(length);
	buffer.set(string.subarray(0, length - 1), 0);
	return buffer;
};

export function readZeroTerminatedString(buffer: ArrayBuffer): Uint8Array {
	let dw = new DataView(buffer);
	let offset = 0;
	let bytes: Array<number> = [];
	while (offset < buffer.byteLength) {
		let byte = dw.getUint8(offset); offset += 1;
		if (byte === 0) {
			break;
		}
		bytes.push(byte);
	}
	return Uint8Array.from(bytes);
};

export type DOSHeader = {
	new_exe_offset: number;
};

export function parseDOSHeader(buffer: ArrayBuffer): DOSHeader {
	let dw = new DataView(buffer);
	let offset = 0;
	let identifier = dw.getUint16(offset, true); offset += 2;
	if (identifier !== 0x5A4D) {
		throw new Error();
	}
	offset += 58;
	let new_exe_offset = dw.getUint32(offset, true); offset += 4;
	return {
		new_exe_offset
	};
};

export enum PEFileHeaderMachineType {
	IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
	IMAGE_FILE_MACHINE_ALPHA = 0x184,
	IMAGE_FILE_MACHINE_ALPHA64 = 0x284,
	IMAGE_FILE_MACHINE_AM33 = 0x1d3,
	IMAGE_FILE_MACHINE_AMD64 = 0x8664,
	IMAGE_FILE_MACHINE_ARM = 0x1c0,
	IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
	IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
	IMAGE_FILE_MACHINE_AXP64 = 0x284,
	IMAGE_FILE_MACHINE_EBC = 0xebc,
	IMAGE_FILE_MACHINE_I386 = 0x14c,
	IMAGE_FILE_MACHINE_IA64 = 0x200,
	IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232,
	IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264,
	IMAGE_FILE_MACHINE_M32R = 0x9041,
	IMAGE_FILE_MACHINE_MIPS16 = 0x266,
	IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
	IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
	IMAGE_FILE_MACHINE_R4000 = 0x166,
	IMAGE_FILE_MACHINE_RISCV32 = 0x5032,
	IMAGE_FILE_MACHINE_RISCV64 = 0x5064,
	IMAGE_FILE_MACHINE_RISCV128 = 0x5128,
	IMAGE_FILE_MACHINE_SH3 = 0x1a2,
	IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
	IMAGE_FILE_MACHINE_SH4 = 0x1a6,
	IMAGE_FILE_MACHINE_SH5 = 0x1a8,
	IMAGE_FILE_MACHINE_THUMB = 0x1c2,
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
};

export enum PEFileHeaderCharacteristics {
	IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
	IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
	IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
	IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
	IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
	IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
	RESERVED_0040 = 0x0040,
	IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
	IMAGE_FILE_32BIT_MACHINE = 0x0100,
	IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
	IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
	IMAGE_FILE_SYSTEM = 0x1000,
	IMAGE_FILE_DLL = 0x2000,
	IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
	IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
};

export type PEFileHeader = {
	machine_type: PEFileHeaderMachineType;
	number_of_sections: number;
	time_date_stamp: number;
	pointer_to_symbol_itable: number;
	number_of_symbols: number;
	size_of_optional_header: number;
	characteristics: number;
};

// 24 b @ 256/224
export function parsePEFileHeader(buffer: ArrayBuffer): PEFileHeader {
	let dw = new DataView(buffer);
	let offset = 0;
	let identifier = dw.getUint32(offset, true); offset += 4;
	if (identifier !== 0x00004550) {
		throw new Error();
	}
	let machine_type = dw.getUint16(offset, true); offset += 2;
	let number_of_sections = dw.getUint16(offset, true); offset += 2;
	let time_date_stamp = dw.getUint32(offset, true); offset += 4;
	let pointer_to_symbol_itable = dw.getUint32(offset, true); offset += 4;
	let number_of_symbols = dw.getUint32(offset, true); offset += 4;
	let size_of_optional_header = dw.getUint16(offset, true); offset += 2;
	let characteristics = dw.getUint16(offset, true); offset += 2;
	return {
		machine_type,
		number_of_sections,
		time_date_stamp,
		pointer_to_symbol_itable,
		number_of_symbols,
		size_of_optional_header,
		characteristics
	};
};

export enum PEOptionalHeaderType {
	PE32 = 0x010B,
	PE32_PLUS = 0x020B
};

export enum PEOptionalHeaderSubsystem {
	IMAGE_SUBSYSTEM_UNKNOWN = 0,
	IMAGE_SUBSYSTEM_NATIVE = 1,
	IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
	IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
	IMAGE_SUBSYSTEM_OS2_CUI = 5,
	IMAGE_SUBSYSTEM_POSIX_CUI = 7,
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
	IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
	IMAGE_SUBSYSTEM_EFI_ROM = 13,
	IMAGE_SUBSYSTEM_XBOX = 14,
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
};

export enum PEOptionalHeaderDLLCharacteristics {
	RESERVED_0001 = 0x0001,
	RESERVED_0002 = 0x0002,
	RESERVED_0004 = 0x0004,
	RESERVED_0008 = 0x0008,
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
	IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
	IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
	IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
};

export type PEOptionalHeaderDataDirectory = {
	virtual_address: number;
	size: number;
};

export enum PEOptionalHeaderDataDirectoryIndex {
	EXPORT_TABLE = 0,
	IMPORT_TABLE = 1,
	RESOURCE_TABLE = 2,
	EXCEPTION_TABLE = 3,
	CERTIFICATE_TABLE = 4,
	BASE_RELOCATION_TABLE = 5,
	DEBUG_TABLE = 6,
	ARCHITECTURE_TABLE = 7,
	GLOBAL_POINTER_TABLE = 8,
	TLS_TABLE = 9,
	LOAD_CONFIG_TABLE = 10,
	BOUND_IMPORT_TABLE = 11,
	IAT_TABLE = 12,
	DELAY_IMPORT_DESCRIPTOR_TABLE = 13,
	CLR_RUNTIME_HEADER_TABLE = 14,
	RESERVED_0015 = 15
};

// 96 bytes (32bit) @280/248
export type PEOptionalHeader = {
	type: PEOptionalHeaderType;
	major_linker_version: number;
	minor_linker_version: number;
	size_of_code: number;
	size_of_initialized_data: number;
	size_of_ununitialized_data: number;
	address_of_entry_point: number;
	base_of_code: number;
	base_of_data?: number;
	image_base: number;
	section_alignment: number;
	file_alignment: number;
	major_operating_system_version: number;
	minor_operating_system_version: number;
	major_image_version: number;
	minor_image_version: number;
	major_subsystem_version: number;
	minor_subsystem_version: number;
	win32_version_value: number;
	size_of_image: number;
	size_of_headers: number;
	checksum: number;
	subsystem: PEOptionalHeaderSubsystem;
	dll_characteristics: number;
	size_of_stack_reserve: number;
	size_of_stack_commit: number;
	size_of_heap_reserve: number;
	size_of_heap_commit: number;
	loader_flags: number;
	number_of_rvas_and_sizes: number;
	data_directories: Array<PEOptionalHeaderDataDirectory>;
};

export function parsePEOptionalHeader(buffer: ArrayBuffer): PEOptionalHeader {
	let dw = new DataView(buffer);
	let offset = 0;
	let type = dw.getUint16(offset, true); offset += 2;
	let major_linker_version = dw.getUint8(offset); offset += 1;
	let minor_linker_version = dw.getUint8(offset); offset += 1;
	let size_of_code = dw.getUint32(offset, true); offset += 4;
	let size_of_initialized_data = dw.getUint32(offset, true); offset += 4;
	let size_of_ununitialized_data = dw.getUint32(offset, true); offset += 4;
	let address_of_entry_point = dw.getUint32(offset, true); offset += 4;
	let base_of_code = dw.getUint32(offset, true); offset += 4;
	if (type === PEOptionalHeaderType.PE32) {
		let base_of_data = dw.getUint32(offset, true); offset += 4;
		let image_base = dw.getUint32(offset, true); offset += 4;
		let section_alignment = dw.getUint32(offset, true); offset += 4;
		let file_alignment = dw.getUint32(offset, true); offset += 4;
		let major_operating_system_version = dw.getUint16(offset, true); offset += 2;
		let minor_operating_system_version = dw.getUint16(offset, true); offset += 2;
		let major_image_version = dw.getUint16(offset, true); offset += 2;
		let minor_image_version = dw.getUint16(offset, true); offset += 2;
		let major_subsystem_version = dw.getUint16(offset, true); offset += 2;
		let minor_subsystem_version = dw.getUint16(offset, true); offset += 2;
		let win32_version_value = dw.getUint32(offset, true); offset += 4;
		let size_of_image = dw.getUint32(offset, true); offset += 4;
		let size_of_headers = dw.getUint32(offset, true); offset += 4;
		let checksum = dw.getUint32(offset, true); offset += 4;
		let subsystem = dw.getUint16(offset, true); offset += 2;
		let dll_characteristics = dw.getUint16(offset, true); offset += 2;
		let size_of_stack_reserve = dw.getUint32(offset, true); offset += 4;
		let size_of_stack_commit = dw.getUint32(offset, true); offset += 4;
		let size_of_heap_reserve = dw.getUint32(offset, true); offset += 4;
		let size_of_heap_commit = dw.getUint32(offset, true); offset += 4;
		let loader_flags = dw.getUint32(offset, true); offset += 4;
		let number_of_rvas_and_sizes = dw.getUint32(offset, true); offset += 4;
		let data_directories: Array<PEOptionalHeaderDataDirectory> = [];
		// 64 bytes @376/348
		for (let i = 0; i < number_of_rvas_and_sizes; i++) {
			let virtual_address = dw.getUint32(offset, true); offset += 4;
			let size = dw.getUint32(offset, true); offset += 4;
			data_directories.push({
				virtual_address,
				size
			});
		}
		return {
			type,
			major_linker_version,
			minor_linker_version,
			size_of_code,
			size_of_initialized_data,
			size_of_ununitialized_data,
			address_of_entry_point,
			base_of_code,
			base_of_data,
			image_base,
			section_alignment,
			file_alignment,
			major_operating_system_version,
			minor_operating_system_version,
			major_image_version,
			minor_image_version,
			major_subsystem_version,
			minor_subsystem_version,
			win32_version_value,
			size_of_image,
			size_of_headers,
			checksum,
			subsystem,
			dll_characteristics,
			size_of_stack_reserve,
			size_of_stack_commit,
			size_of_heap_reserve,
			size_of_heap_commit,
			loader_flags,
			number_of_rvas_and_sizes,
			data_directories
		};
	} else {
		let base_of_data = undefined;
		let image_base = Number(dw.getBigUint64(offset, true)); offset += 8;
		let section_alignment = dw.getUint32(offset, true); offset += 4;
		let file_alignment = dw.getUint32(offset, true); offset += 4;
		let major_operating_system_version = dw.getUint16(offset, true); offset += 2;
		let minor_operating_system_version = dw.getUint16(offset, true); offset += 2;
		let major_image_version = dw.getUint16(offset, true); offset += 2;
		let minor_image_version = dw.getUint16(offset, true); offset += 2;
		let major_subsystem_version = dw.getUint16(offset, true); offset += 2;
		let minor_subsystem_version = dw.getUint16(offset, true); offset += 2;
		let win32_version_value = dw.getUint32(offset, true); offset += 4;
		let size_of_image = dw.getUint32(offset, true); offset += 4;
		let size_of_headers = dw.getUint32(offset, true); offset += 4;
		let checksum = dw.getUint32(offset, true); offset += 4;
		let subsystem = dw.getUint16(offset, true); offset += 2;
		let dll_characteristics = dw.getUint16(offset, true); offset += 2;
		let size_of_stack_reserve = Number(dw.getBigUint64(offset, true)); offset += 8;
		let size_of_stack_commit = Number(dw.getBigUint64(offset, true)); offset += 8;
		let size_of_heap_reserve = Number(dw.getBigUint64(offset, true)); offset += 8;
		let size_of_heap_commit = Number(dw.getBigUint64(offset, true)); offset += 8;
		let loader_flags = dw.getUint32(offset, true); offset += 4;
		let number_of_rvas_and_sizes = dw.getUint32(offset, true); offset += 4;
		let data_directories: Array<PEOptionalHeaderDataDirectory> = [];
		for (let i = 0; i < number_of_rvas_and_sizes; i++) {
			let virtual_address = dw.getUint32(offset, true); offset += 4;
			let size = dw.getUint32(offset, true); offset += 4;
			data_directories.push({
				virtual_address,
				size
			});
		}
		return {
			type,
			major_linker_version,
			minor_linker_version,
			size_of_code,
			size_of_initialized_data,
			size_of_ununitialized_data,
			address_of_entry_point,
			base_of_code,
			base_of_data,
			image_base,
			section_alignment,
			file_alignment,
			major_operating_system_version,
			minor_operating_system_version,
			major_image_version,
			minor_image_version,
			major_subsystem_version,
			minor_subsystem_version,
			win32_version_value,
			size_of_image,
			size_of_headers,
			checksum,
			subsystem,
			dll_characteristics,
			size_of_stack_reserve,
			size_of_stack_commit,
			size_of_heap_reserve,
			size_of_heap_commit,
			loader_flags,
			number_of_rvas_and_sizes,
			data_directories
		};
	}
};

export enum PESectionFlags {
	RESERVED_00000000 = 0x00000000,
	RESERVED_00000001 = 0x00000001,
	RESERVED_00000002 = 0x00000002,
	RESERVED_00000004 = 0x00000004,
	IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
	RESERVED_00000010 = 0x00000010,
	IMAGE_SCN_CNT_CODE = 0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
	IMAGE_SCN_LNK_OTHER = 0x00000100,
	IMAGE_SCN_LNK_INFO = 0x00000200,
	RESERVED_00000400 = 0x00000400,
	IMAGE_SCN_LNK_REMOVE = 0x00000800,
	IMAGE_SCN_LNK_COMDAT = 0x00001000,
	IMAGE_SCN_GPREL = 0x00008000,
	IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
	IMAGE_SCN_MEM_16BIT = 0x00020000,
	IMAGE_SCN_MEM_LOCKED = 0x00040000,
	IMAGE_SCN_MEM_PRELOAD = 0x00080000,
	IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
	IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
	IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
	IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
	IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
	IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
	IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
	IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
	IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
	IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
	IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
	IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
	IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
	IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
	IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
	IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
	IMAGE_SCN_MEM_SHARED = 0x10000000,
	IMAGE_SCN_MEM_EXECUTE = 0x20000000,
	IMAGE_SCN_MEM_READ = 0x40000000,
	IMAGE_SCN_MEM_WRITE = 0x80000000
};

export type PESectionHeader = {
	name: string;
	virtual_size: number;
	virtual_address: number;
	size_of_raw_data: number;
	pointer_to_raw_data: number;
	pointer_to_relocations: number;
	pointer_to_line_numbers: number;
	number_of_relocations: number;
	number_of_line_numbers: number;
	characteristics: number;
};

export function parsePESectionHeader(buffer: ArrayBuffer): PESectionHeader {
	let dw = new DataView(buffer);
	let offset = 0;
	let name = Chunk.toString(readZeroTerminatedString(buffer.slice(offset, offset + 8)), "utf-8"); offset += 8;
	let virtual_size = dw.getUint32(offset, true); offset += 4;
	let virtual_address = dw.getUint32(offset, true); offset += 4;
	let size_of_raw_data = dw.getUint32(offset, true); offset += 4;
	let pointer_to_raw_data = dw.getUint32(offset, true); offset += 4;
	let pointer_to_relocations = dw.getUint32(offset, true); offset += 4;
	let pointer_to_line_numbers = dw.getUint32(offset, true); offset += 4;
	let number_of_relocations = dw.getUint16(offset, true); offset += 2;
	let number_of_line_numbers = dw.getUint16(offset, true); offset += 2;
	let characteristics = dw.getUint32(offset, true); offset += 4;
	return {
		name,
		virtual_size,
		virtual_address,
		size_of_raw_data,
		pointer_to_raw_data,
		pointer_to_relocations,
		pointer_to_line_numbers,
		number_of_relocations,
		number_of_line_numbers,
		characteristics
	};
};

export function serializePESectionHeader(section: PESectionHeader): Uint8Array {
	let buffer = new Uint8Array(40);
	let dw = new DataView(buffer.buffer);
	let offset = 0;
	buffer.set(zeroTerminate(Chunk.fromString(section.name, "utf-8"), 8), offset); offset += 8;
	dw.setUint32(offset, section.virtual_size, true); offset += 4;
	dw.setUint32(offset, section.virtual_address, true); offset += 4;
	dw.setUint32(offset, section.size_of_raw_data, true); offset += 4;
	dw.setUint32(offset, section.pointer_to_raw_data, true); offset += 4;
	dw.setUint32(offset, section.pointer_to_relocations, true); offset += 4;
	dw.setUint32(offset, section.pointer_to_line_numbers, true); offset += 4;
	dw.setUint16(offset, section.number_of_relocations, true); offset += 2;
	dw.setUint16(offset, section.number_of_line_numbers, true); offset += 2;
	dw.setUint32(offset, section.characteristics, true); offset += 4;
	return buffer;
};

export function getVirtualPESectionData(buffer: ArrayBuffer, section_header: PESectionHeader): Uint8Array {
	let data = new Uint8Array(section_header.virtual_size);
	data.set(new Uint8Array(buffer.slice(section_header.pointer_to_raw_data, section_header.pointer_to_raw_data + Math.min(section_header.virtual_size, section_header.size_of_raw_data))), 0);
	return data;
};

export function getRawPESectionData(buffer: ArrayBuffer, section_header: PESectionHeader): Uint8Array {
	let data = new Uint8Array(section_header.size_of_raw_data);
	data.set(new Uint8Array(buffer.slice(section_header.pointer_to_raw_data, section_header.pointer_to_raw_data + section_header.size_of_raw_data)), 0);
	return data;
};

export type PEImportDirectoryTableThunkEntry = {
	type: "ordinal";
	value: number;
} | {
	type: "name",
	rva: number;
	hint: number;
	name: string;
};

export type PEImportDirectoryTable = {
	original_first_thunk_rva: number;
	time_date_stamp: number;
	forwarder_chain: number;
	name_rva: number;
	first_thunk_rva: number;
	name: string;
};

export function readPEImportDirectoryTableThunkEntries(file_buffer: ArrayBuffer, optional_header: PEOptionalHeader, import_directory_table: PEImportDirectoryTable, section_header: PESectionHeader): Array<PEImportDirectoryTableThunkEntry> {
	let data = getVirtualPESectionData(file_buffer, section_header).buffer;
	let dw = new DataView(data);
	let thunks: Array<PEImportDirectoryTableThunkEntry> = [];
	while (true) {
		if (optional_header.type === PEOptionalHeaderType.PE32) {
			let entry = dw.getUint32(import_directory_table.original_first_thunk_rva - section_header.virtual_address + thunks.length * 4, true);
			if (entry === 0) {
				break;
			}
			if (entry & 0x80000000) {
				thunks.push({
					type: "ordinal",
					value: entry & 0xFFFF
				});
			} else {
				let rva = entry;
				let hint = dw.getUint16(rva - section_header.virtual_address, true);
				let name = Chunk.toString(readZeroTerminatedString(data.slice(rva - section_header.virtual_address + 2)), "binary");
				thunks.push({
					type: "name",
					rva,
					hint,
					name
				});
			}
		} else {
			let entry = dw.getBigUint64(import_directory_table.original_first_thunk_rva - section_header.virtual_address + thunks.length * 8, true);
			if (entry === 0n) {
				break;
			}
			if (entry & 0x8000000000000000n) {
				thunks.push({
					type: "ordinal",
					value: Number(entry & 0xFFFFn)
				});
			} else {
				let rva = Number(entry);
				let hint = dw.getUint16(rva - section_header.virtual_address, true);
				let name = Chunk.toString(readZeroTerminatedString(data.slice(rva - section_header.virtual_address + 2)), "binary");
				thunks.push({
					type: "name",
					rva,
					hint,
					name
				});
			}
		}
	}
	return thunks;
};

export function readPEImportDirectoryTableThunks(offset: number, dw: DataView, optional_header: PEOptionalHeader): Array<number> {
	let thunks: Array<number> = [];
	while (true) {
		if (optional_header.type === PEOptionalHeaderType.PE32) {
			let entry = dw.getUint32(offset + thunks.length * 4, true);
			if (entry === 0) {
				break;
			}
			thunks.push(entry);
		} else {
			let entry = dw.getBigUint64(offset + thunks.length * 8, true);
			if (entry === 0n) {
				break;
			}
			thunks.push(Number(entry)); // breaks ordinal type
		}
	}
	return thunks;
};

export function getSectionHeaderContainingEntryPoint(optional_header: PEOptionalHeader, section_headers: Array<PESectionHeader>): { section_header: PESectionHeader; offset: number; } {
	let address_of_entry_point = optional_header.address_of_entry_point;
	let section_header = section_headers.find((section_header) => {
		if (section_header.pointer_to_raw_data <= address_of_entry_point) {
			if (section_header.pointer_to_raw_data + section_header.size_of_raw_data > address_of_entry_point) {
				return true;
			}
		}
		return false;
	});
	if (section_header == null) {
		throw new Error(`Expected a single section containing the entry point!`);
	}
	let offset = address_of_entry_point - section_header.pointer_to_raw_data;
	console.log(`Entry point is at absolute offset ${address_of_entry_point}, offset ${offset} in ${section_header.name} (section address delta ${section_header.pointer_to_raw_data - section_header.virtual_address}).`);
	return {
		section_header,
		offset
	};
};

export function getSectionHeaderContainingImportTable(optional_header: PEOptionalHeader, section_headers: Array<PESectionHeader>): { section_header: PESectionHeader; offset: number; } {
	let import_table = optional_header.data_directories[PEOptionalHeaderDataDirectoryIndex.IMPORT_TABLE];
	let section_header = section_headers.find((section_header) => {
		if (section_header.virtual_address <= import_table.virtual_address) {
			if (section_header.virtual_address + section_header.virtual_size >= import_table.virtual_address + import_table.size) {
				return true;
			}
		}
		return false;
	});
	if (section_header == null) {
		throw new Error(`Expected a single section containing the entire import table!`);
	}
	let offset = import_table.virtual_address - section_header.virtual_address;
	console.log(`Import table is at offset ${offset} in ${section_header.name} (section address delta ${section_header.pointer_to_raw_data - section_header.virtual_address}).`);
	return {
		section_header,
		offset
	};
};

export function readPEImportDirectoryTable(buffer: ArrayBuffer, section_header: PESectionHeader, offset: number): { import_directory_table: Array<PEImportDirectoryTable>; } {
	let idata_buffer = getVirtualPESectionData(buffer, section_header).buffer;
	let dw = new DataView(idata_buffer);
	let import_directory_entries: Array<PEImportDirectoryTable> = [];
	while (true) {
		let original_first_thunk_rva = dw.getUint32(offset, true); offset += 4;
		let time_date_stamp = dw.getUint32(offset, true); offset += 4;
		let forwarder_chain = dw.getUint32(offset, true); offset += 4;
		let name_rva = dw.getUint32(offset, true); offset += 4;
		let first_thunk_rva = dw.getUint32(offset, true); offset += 4;
		if (original_first_thunk_rva === 0 && time_date_stamp === 0 && forwarder_chain === 0 && name_rva === 0 && first_thunk_rva === 0) {
			break;
		}
		let name = Chunk.toString(readZeroTerminatedString(idata_buffer.slice(name_rva - section_header.virtual_address)), "binary");
		import_directory_entries.push({
			original_first_thunk_rva,
			time_date_stamp,
			forwarder_chain,
			name_rva,
			first_thunk_rva,
			name
		});
	}
	return {
		import_directory_table: import_directory_entries
	};
};

export function writePEImportDirectoryTable(buffer: ArrayBuffer, optional_header: PEOptionalHeader, section_headers: Array<PESectionHeader>, import_directory_tables: PEImportDirectoryTable[]): void {
	let import_table = optional_header.data_directories[PEOptionalHeaderDataDirectoryIndex.IMPORT_TABLE];
	let section_header = section_headers.find((section_header) => {
		if (section_header.virtual_address <= import_table.virtual_address) {
			if (section_header.virtual_address + section_header.virtual_size >= import_table.virtual_address + import_table.size) {
				return true;
			}
		}
		return false;
	});
	if (section_header == null) {
		throw new Error(`Expected a single section containing the entire import table!`);
	}
	let delta = import_table.virtual_address - section_header.virtual_address;
	let idata_buffer = getVirtualPESectionData(buffer, section_header);
	let dw = new DataView(idata_buffer.buffer);
	let offset = delta;
	for (let table of import_directory_tables) {
		dw.setUint32(offset, table.original_first_thunk_rva, true); offset += 4;
		dw.setUint32(offset, table.time_date_stamp, true); offset += 4;
		dw.setUint32(offset, table.forwarder_chain, true); offset += 4;
		dw.setUint32(offset, table.name_rva, true); offset += 4;
		dw.setUint32(offset, table.first_thunk_rva, true); offset += 4;
/* 		for (let [index, thunk] of table.thunks.entries()) {
			if (optional_header.type === PEOptionalHeaderType.PE32) {
				dw.setUint32(table.original_first_thunk_rva - section_header.virtual_address + index * 4, Number(thunk), true);
			} else {
				dw.setBigUint64(table.original_first_thunk_rva - section_header.virtual_address + index * 8, thunk, true);
			}
		} */
		// write zero thunk
	}
	new Uint8Array(buffer).set(idata_buffer.subarray(0, section_header.size_of_raw_data), section_header.pointer_to_raw_data);
	// write zero table
};

type Cursor = {
	offset: number;
};

export type PEResourceDirectoryEntry = {
	name: number;
	name_is_id: number;
	offset_to_data: number;
};

export const PEResourceDirectoryEntry = {
	read(array: Uint8Array, cursor?: Cursor): PEResourceDirectoryEntry {
		cursor = cursor ?? { offset: 0 };
		let dw = new DataView(array.buffer, array.byteOffset, array.byteLength);
		let name = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let dword = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let name_is_id = (dword >>> 31) & 0x00000001;
		let offset_to_data = (dword >>> 0) & 0x7FFFFFFF;
		return {
			name,
			name_is_id,
			offset_to_data
		};
	}
};

export type PEResourceDirectory = {
	characteristics: number;
	time_date_stamp: number;
	major_version: number;
	minor_version: number;
	number_of_named_entries: number;
	number_of_id_entries: number;
};

export const PEResourceDirectory = {
	read(array: Uint8Array, cursor?: Cursor): PEResourceDirectory {
		cursor = cursor ?? { offset: 0 };
		let dw = new DataView(array.buffer, array.byteOffset, array.byteLength);
		let characteristics = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let time_date_stamp = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let major_version = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		let minor_version = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		let number_of_named_entries = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		let number_of_id_entries = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		return {
			characteristics,
			time_date_stamp,
			major_version,
			minor_version,
			number_of_named_entries,
			number_of_id_entries
		};
	},

	readWithEntries(array: Uint8Array, cursor?: Cursor): PEResourceDirectory & {
		entries: Array<PEResourceDirectoryEntry>;
	} {
		cursor = cursor ?? { offset: 0 };
		let header = this.read(array, cursor);
		let entries: Array<PEResourceDirectoryEntry> = [];
		for (let i = 0; i < header.number_of_id_entries; i++) {
			entries.push(PEResourceDirectoryEntry.read(array, cursor));
		}
		for (let i = 0; i < header.number_of_named_entries; i++) {
			entries.push(PEResourceDirectoryEntry.read(array, cursor));
		}
		return {
			...header,
			entries
		};
	}
};

export type PEResourceDirStringU = {
	length: number;
	name_string: number;
};

export const PEResourceDirStringU = {
	read(array: Uint8Array, cursor?: Cursor): PEResourceDirStringU {
		cursor = cursor ?? { offset: 0 };
		let dw = new DataView(array.buffer, array.byteOffset, array.byteLength);
		let length = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		let name_string = dw.getUint16(cursor.offset, true); cursor.offset += 2;
		return {
			length,
			name_string
		};
	}
};

export type PEResourceDataEntry = {
	rva_of_data: number;
	size: number;
	code_page: number;
	reserved: number;
};

export const PEResourceDataEntry = {
	read(array: Uint8Array, cursor?: Cursor): PEResourceDataEntry {
		cursor = cursor ?? { offset: 0 };
		let dw = new DataView(array.buffer, array.byteOffset, array.byteLength);
		let rva_of_data = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let size = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let code_page = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		let reserved = dw.getUint32(cursor.offset, true); cursor.offset += 4;
		return {
			rva_of_data,
			size,
			code_page,
			reserved
		};
	},

	serialize(record: PEResourceDataEntry, array?: Uint8Array, cursor?: Cursor): Uint8Array {
		array = array ?? new Uint8Array(16);
		cursor = cursor ?? { offset: 0 };
		let dw = new DataView(array.buffer, array.byteOffset, array.byteLength);
		dw.setUint32(cursor.offset, record.rva_of_data, true); cursor.offset += 4;
	 	dw.setUint32(cursor.offset, record.size, true); cursor.offset += 4;
		dw.setUint32(cursor.offset, record.code_page, true); cursor.offset += 4;
		dw.setUint32(cursor.offset, record.reserved, true); cursor.offset += 4;
		return array;
	}
};

export const RSRC = {
	rebase(array: Uint8Array, virtual_address_delta: number): Uint8Array {
		let rebased = array.slice();
		let root = PEResourceDirectory.readWithEntries(array);
		for (let entry of root.entries) {
			let offset = entry.offset_to_data;
			let subentry = PEResourceDirectory.readWithEntries(array, { offset });
			for (let entry of subentry.entries) {
				let offset = entry.offset_to_data;
				let subentry = PEResourceDirectory.readWithEntries(array, { offset });
				for (let entry of subentry.entries) {
					let offset = entry.offset_to_data;
					let subentry = PEResourceDataEntry.read(array, { offset });
					subentry.rva_of_data += virtual_address_delta;
					PEResourceDataEntry.serialize(subentry, rebased, { offset });
				}
			}
		}
		return rebased;
	}
};
