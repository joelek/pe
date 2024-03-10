import * as fs from "fs"

let last_seek_lba: number | undefined = undefined;

enum CDBCode {
	INQUIRY = 0x12,
	READ = 0x28,
	SEEK = 0x2B,
	READ_SUBCHANNEL = 0x42,
	READ_CD = 0xBE
};

// Works for MSF in q-channel.
function formatAddress(address: number, is_msf: boolean): string {
	if (is_msf) {
		let m = (address >>> 16) & 0xFF;
		let s = (address >>> 8) & 0xFF;
		let f = (address >>> 0) & 0xFF;
		return `${m.toString(10).padStart(2, "0")}:${s.toString(10).padStart(2, "0")}:${f.toString(10).padStart(2, "0")}`;
	} else {
		return `${address}`;
	}
};

function unwrapBCD(number: number): number {
	let mh = (number >> 20) & 0x0F;
	let ml = (number >> 16) & 0x0F;
	let sh = (number >> 12) & 0x0F;
	let sl = (number >> 8) & 0x0F;
	let fh = (number >> 4) & 0x0F;
	let fl = (number >> 0) & 0x0F;
	let m = mh * 10 + ml;
	let s = sh * 10 + sl
	let f = fh * 10 + fl;
	return (m << 16) | (s << 8) | f;
};

function parseCdb(buffer: Uint8Array, output_buffer: Uint8Array): void {
	let dw = new DataView(buffer.buffer, buffer.byteOffset);
	let offset = 0;
	let code = dw.getUint8(offset); offset += 1;
	if (code === CDBCode.INQUIRY) {
		// https://enos.itcollege.ee/~edmund/storage/loengud/varasem/SAN_IPSAN_NAS_CAS/SCSI-command-reference-manual.pdf page 76 (pdf page 92)
		process.stdout.write(`(UNPARSED ${CDBCode[code]})\n`);
	} else if (code === CDBCode.READ) {
		// https://www.t10.org/ftp/t10/document.05/05-344r0.pdf page 47 (pdf page 63)
		let flags_one = dw.getUint8(offset); offset += 1;
		let lba = dw.getUint32(offset, false); offset += 4;
		let flags_two = dw.getUint8(offset); offset += 1;
		let blocks_to_transfer = dw.getUint16(offset, false); offset += 2;
		process.stdout.write(`READ lba:${lba} (${lba+150}) blocks_to_transfer:${blocks_to_transfer}\n`);
	} else if (code === CDBCode.SEEK) {
		let flags = dw.getUint8(offset); offset += 1;
		let lba = dw.getUint32(offset, false); offset += 4;
		process.stdout.write(`SEEK lba:${lba} (${lba+150})\n`);
		last_seek_lba = lba;
	} else if (code === CDBCode.READ_SUBCHANNEL) {
		// https://www.13thmonkey.org/documentation/SCSI/mmc3r10g.pdf page 205 (pdf page 241)
		let flags = dw.getUint16(offset, false); offset += 2;
		let time = (flags >> 9) & 0x0001;
		let subq = (flags >> 6) & 0x0001;
		let parameter_list = dw.getUint8(offset); offset += 1;
		let reserved_one = dw.getUint8(offset); offset += 1;
		let reserved_two = dw.getUint8(offset); offset += 1;
		let track_number = dw.getUint8(offset); offset += 1;
		let allocation_length = dw.getUint16(offset, false); offset += 2;
		let control = dw.getUint8(offset); offset += 1;
		{
			let odw = new DataView(output_buffer.buffer, output_buffer.byteOffset);
			let offset = 0;
			odw.getUint8(offset); offset += 1;
			let audio_status = odw.getUint8(offset); offset += 1;
			let subchannel_data_length = odw.getUint16(offset, false); offset += 2;
			let subchannel_data_format_code = odw.getUint8(offset); offset += 1;
			let flags = odw.getUint8(offset); offset += 1;
			let adr = (flags >> 4) & 0b00001111;
			let control = (flags >> 0) & 0b00001111;
			let track_number = odw.getUint8(offset); offset += 1;
			let index_number = odw.getUint8(offset); offset += 1;
			let absolute_address = odw.getUint32(offset, false); offset += 4;
			let relative_address = odw.getUint32(offset, false); offset += 4;
			let lba_diff = computeLBAFromMSF(relative_address) - (last_seek_lba ?? 0);
			process.stdout.write(`READ_SUBCHANNEL => absolute:${formatAddress(absolute_address, time === 1)} (${computeLBAFromMSF(absolute_address)}), relative:${formatAddress(relative_address, time === 1)} (${computeLBAFromMSF(relative_address)}), lba_seek_diff=${lba_diff}\n`);
		}
	} else if (code === CDBCode.READ_CD) {
		// https://www.13thmonkey.org/documentation/SCSI/mmc3r10g.pdf page 156 (pdf page 192)
		let flags_one = dw.getUint8(offset); offset += 1;
		let expected_sector_type = (flags_one >> 2) & 0b111;
		let relative_address = (flags_one >> 0) & 0b1;
		let lba = dw.getUint32(offset, false); offset += 4;
		let blocks_to_transfer = (dw.getUint8(offset) << 16) | dw.getUint16(offset + 1, false); offset += 3;
		let flags_two = dw.getUint8(offset); offset += 1;
		let sync = (flags_two >> 7) & 0b1;
		let header_codes = (flags_two >> 5) & 0b11;
		let user_data = (flags_two >> 4) & 0b1;
		let edc_and_ecc = (flags_two >> 3) & 0b1;
		let error_field = (flags_two >> 1) & 0b11;
		let reserved_flag = (flags_two >> 0) & 0b1;
		{
			let odw = new DataView(output_buffer.buffer, output_buffer.byteOffset);
			let offset = 0;
			offset += 12;
			let address = unwrapBCD((odw.getUint8(offset) << 16) | odw.getUint16(offset + 1, false)); offset += 3;
			process.stdout.write(`READ_CD lba:${lba} (${lba+150}) blocks_to_transfer:${blocks_to_transfer} sync:${sync} header_codes:${header_codes} user_data:${user_data} edc_and_ecc:${edc_and_ecc} error_field:${error_field} reserved_flag:${reserved_flag} => address:${formatAddress(address, true)} (${computeLBAFromMSF(address)})}\n`);
		}
	} else {
		process.stdout.write(`(UNPARSED ${CDBCode[code]})\n`);
	}
};

/*

https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_scsi_pass_through

typedef struct _SCSI_PASS_THROUGH {
  USHORT    Length;
  UCHAR     ScsiStatus;
  UCHAR     PathId;
  UCHAR     TargetId;
  UCHAR     Lun;
  UCHAR     CdbLength;
  UCHAR     SenseInfoLength;
  UCHAR     DataIn;
  ULONG     DataTransferLength;
  ULONG     TimeOutValue;
  ULONG_PTR DataBufferOffset;
  ULONG     SenseInfoOffset;
  UCHAR     Cdb[16];
} SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

*/
function parse_IOCTL_SCSI_PASS_THROUGH(input_buffer: Uint8Array, output_buffer: Uint8Array): void {
	let dw = new DataView(input_buffer.buffer, input_buffer.byteOffset);
	let offset = 0;
	let Length = dw.getUint16(offset, true); offset += 2;
	let ScsiStatus = dw.getUint8(offset); offset += 1;
	let PathId = dw.getUint8(offset); offset += 1;
	let TargetId = dw.getUint8(offset); offset += 1;
	let Lun = dw.getUint8(offset); offset += 1;
	let CdbLength = dw.getUint8(offset); offset += 1;
	let SenseInfoLength = dw.getUint8(offset); offset += 1;
	let DataIn = dw.getUint8(offset); offset += 1;
	offset = ((offset + 3) >> 2) << 2; // Align to 32-bit boundary.
	let DataTransferLength = dw.getUint32(offset, true); offset += 4;
	let TimeOutValue = dw.getUint32(offset, true); offset += 4;
	let DataBufferOffset = dw.getUint32(offset, true); offset += 4;
	let SenseInfoOffset = dw.getUint32(offset, true); offset += 4;
	let Cdb = input_buffer.subarray(offset, offset + CdbLength); offset += 16;
	parseCdb(Cdb, output_buffer.subarray(DataBufferOffset));
};

/*

https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ns-ntddscsi-_scsi_pass_through_direct

typedef struct _SCSI_PASS_THROUGH_DIRECT {
  USHORT Length;
  UCHAR  ScsiStatus;
  UCHAR  PathId;
  UCHAR  TargetId;
  UCHAR  Lun;
  UCHAR  CdbLength;
  UCHAR  SenseInfoLength;
  UCHAR  DataIn;
  ULONG  DataTransferLength;
  ULONG  TimeOutValue;
  PVOID  DataBuffer;	// pointer not offset
  ULONG  SenseInfoOffset;
  UCHAR  Cdb[16];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

*/
function parse_IOCTL_SCSI_PASS_THROUGH_DIRECT(input_buffer: Uint8Array, output_buffer: Uint8Array): void {
	let dw = new DataView(input_buffer.buffer, input_buffer.byteOffset);
	let offset = 0;
	let Length = dw.getUint16(offset, true); offset += 2;
	let ScsiStatus = dw.getUint8(offset); offset += 1;
	let PathId = dw.getUint8(offset); offset += 1;
	let TargetId = dw.getUint8(offset); offset += 1;
	let Lun = dw.getUint8(offset); offset += 1;
	let CdbLength = dw.getUint8(offset); offset += 1;
	let SenseInfoLength = dw.getUint8(offset); offset += 1;
	let DataIn = dw.getUint8(offset); offset += 1;
	offset = ((offset + 3) >> 2) << 2; // Align to 32-bit boundary.
	let DataTransferLength = dw.getUint32(offset, true); offset += 4;
	let TimeOutValue = dw.getUint32(offset, true); offset += 4;
	let DataBuffer = dw.getUint32(offset, true); offset += 4;
	let SenseInfoOffset = dw.getUint32(offset, true); offset += 4;
	let Cdb = input_buffer.subarray(offset, offset + CdbLength); offset += 16;
	parseCdb(Cdb, output_buffer);
};

// Works for TOC MSFs and subq MSFs.
function computeLBAFromMSF(address: number): number {
	let m = (address >> 16) & 0xFF;
	let s = (address >> 8) & 0xFF;
	let f = (address >> 0) & 0xFF;
	return (((m * 60) + s) * 75) + f;
};

/*

typedef struct _TRACK_DATA
{
    UCHAR Reserved;
    UCHAR Control : 4;
    UCHAR Adr : 4;
    UCHAR TrackNumber;
    UCHAR Reserved1;
    UCHAR Address[4];
} TRACK_DATA;

typedef struct _CDROM_TOC
{
    UCHAR Length[2];
    UCHAR FirstTrack;
    UCHAR LastTrack;
    TRACK_DATA TrackData[100];
} CDROM_TOC;

Lead out track follows track with index 0 (has track number 170 = 0xAA)

is rest junk?
	need to check bytes written

*/
function parse_IOCTL_CDROM_READ_TOC(input_buffer: Uint8Array, output_buffer: Uint8Array) {
	let dw = new DataView(input_buffer.buffer, input_buffer.byteOffset);
	let offset = 0;
	let byte_length = dw.getUint16(offset, false); offset += 2;
	let first_track = dw.getUint8(offset); offset += 1;
	let last_track = dw.getUint8(offset); offset += 1;
	let tracks: Array<{
		reserved_one: number;
		control: number;
		adr: number;
		track_number: number;
		reserved_two: number;
		address: number;
		address_alba: number;
	}> = [];
	for (let i = 0; i < 100; i++) {
		let reserved_one = dw.getUint8(offset); offset += 1;
		let packed_one = dw.getUint8(offset); offset += 1;
		let control = (packed_one >> 0) & 0b1111;
		let adr = (packed_one >> 4) & 0b1111;
		let track_number = dw.getUint8(offset); offset += 1;
		let reserved_two = dw.getUint8(offset); offset += 1;
		let address = dw.getUint32(offset, false); offset += 4;
		let address_alba = computeLBAFromMSF(address);
		tracks.push({
			reserved_one,
			control,
			adr,
			track_number,
			reserved_two,
			address,
			address_alba
		});
	}
	process.stdout.write(`\n`);
	return {
		byte_length,
		first_track,
		last_track,
		tracks
	};
};

function parse_IOCTL_STORAGE_MEDIA_REMOVAL(input_buffer: Uint8Array, output_buffer: Uint8Array) {
	let dw = new DataView(input_buffer.buffer, input_buffer.byteOffset);
	let offset = 0;
	let disable_media_removal = dw.getUint8(offset); offset += 1;
	process.stdout.write(`disable_media_removal=${disable_media_removal}\n`);
	return {
		disable_media_removal
	};
};

let numbers = fs.readdirSync(process.argv[2])
	.map((name) => {
		let parts = /^event_([0-9]+).bin$/.exec(name);
		if (parts == null) {
			return;
		}
		let number = Number.parseInt(parts[1]);
		return number;
	})
	.filter((number): number is number => number != null)
	.sort((one, two) => one - two);
const IOCTL_CODES = new Map<number, string>;
let lines = fs.readFileSync("./public/x32dbg/ioctls.txt", "binary").split(/\r?\n/);
for (let line of lines) {
	let parts = line.split(" = ");
	if (parts.length !== 2) {
		continue;
	}
	IOCTL_CODES.set(Number.parseInt(parts[0], 16), parts[1]);
}
for (let number of numbers) {
	let buffer = Uint8Array.from(fs.readFileSync(`${process.argv[2]}event_${number}.bin`));
	let dw = new DataView(buffer.buffer);
	let offset = 0;
	let hDevice = dw.getUint32(offset, true); offset += 4;
	let dwIoControlCode = dw.getUint32(offset, true); offset += 4;
	let lpInBuffer = dw.getUint32(offset, true); offset += 4;
	let nInBufferSize = dw.getUint32(offset, true); offset += 4;
	let lpOutBuffer = dw.getUint32(offset, true); offset += 4;
	let nOutBufferSize = dw.getUint32(offset, true); offset += 4;
	let lpBytesReturned = dw.getUint32(offset, true); offset += 4;
	let lpOverlapped = dw.getUint32(offset, true); offset += 4;
	let input_buffer = buffer.subarray(offset, offset + nInBufferSize); offset += nInBufferSize;
	let output_buffer = buffer.subarray(offset, offset + nOutBufferSize); offset += nOutBufferSize;
	let ioctl_code = IOCTL_CODES.get(dwIoControlCode);
	if (ioctl_code === "IOCTL_SCSI_PASS_THROUGH") {
		process.stdout.write(`event_${number}.bin: IOCTL_SCSI_PASS_THROUGH `);
		parse_IOCTL_SCSI_PASS_THROUGH(input_buffer, output_buffer);
	} else if (ioctl_code === "IOCTL_SCSI_PASS_THROUGH_DIRECT") {
		process.stdout.write(`event_${number}.bin: IOCTL_SCSI_PASS_THROUGH_DIRECT `);
		parse_IOCTL_SCSI_PASS_THROUGH_DIRECT(input_buffer, output_buffer);
	} else if (ioctl_code === "IOCTL_CDROM_READ_TOC") {
		process.stdout.write(`event_${number}.bin: IOCTL_CDROM_READ_TOC `);
		let toc = parse_IOCTL_CDROM_READ_TOC(input_buffer, output_buffer);
/* 		console.log(toc); */
	} else if (ioctl_code === "IOCTL_STORAGE_MEDIA_REMOVAL") {
		process.stdout.write(`event_${number}.bin: IOCTL_STORAGE_MEDIA_REMOVAL `);
		let toc = parse_IOCTL_STORAGE_MEDIA_REMOVAL(input_buffer, output_buffer);
	} else {
		process.stdout.write(`event_${number}.bin: (UNPARSED ${IOCTL_CODES.get(dwIoControlCode)})\n`);
	}
}


/*
The basic red-book CD-ROM standard for audio CDs divides a CD into logical sectors that each contain 2352 bytes (the actual raw sectors contain additional bytes for error detection and correction and control). The yellow-book standard is an outgrowth of the red-book standard, and provides a standard format for storing computer data on a CD, otherwise known as a CD-ROM. The yellow-book standard defines two modes for storing data, named unimaginatively but practically, mode 1 and mode 2. Both start with the original red-book logical sector size of 2352 bytes. Mode 1 divides those 2352 bytes into 12 synchronization bytes, 4 header bytes, 2048 bytes of user data, and 288 bytes of EDC (error detection code) and ECC (error correcting code). Mode 2 divides the 2352 bytes into 12 synchronization bytes, 4 header bytes, and 2336 bytes of user data.




CHECK BCD coding of all MSF:s in code above!


MSF+150 = 1:19:15 => 5790 LBA


12 + 4 + 2048 + 288 = 2352


there is 12 byte junk at end of PVD


*/
