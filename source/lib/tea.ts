const DELTA = 0x9E3779B9;

export function encrypt_chunk(d0: number, d1: number, k0: number, k1: number, k2: number, k3: number): { e0: number, e1: number } {
	let e0 = d0;
	let e1 = d1;
	let sum = 0;
	for (let i = 0; i < 32; i++) {
		sum = (sum + DELTA) >>> 0;
		let a = (e1 << 4) >>> 0;
		let b = (a + k0) >>> 0;
		let c = (e1 + sum) >>> 0;
		let d = (e1 >>> 5) >>> 0;
		let e = (d + k1) >>> 0;
		let f = (b ^ c) >>> 0;
		let g = (f ^ e) >>> 0;
		e0 = (e0 + g) >>> 0;
		let h = (e0 << 4) >>> 0;
		let i = (h + k2) >>> 0;
		let j = (e0 + sum) >>> 0;
		let k = (e0 >>> 5) >>> 0;
		let l = (k + k3) >>> 0;
		let m = (i ^ j) >>> 0;
		let n = (m ^l ) >>> 0;
		e1 = (e1 + n) >>> 0;
	}
	return {
		e0,
		e1
	};
};

export function decrypt_chunk(e0: number, e1: number, k0: number, k1: number, k2: number, k3: number): { d0: number, d1: number } {
	let d0 = e0;
	let d1 = e1;
	let sum = 0xC6EF3720;
	for (let i = 0; i < 32; i++) {
		let a = (d0 << 4) >>> 0;
		let b = (a + k2) >>> 0;
		let c = (d0 + sum) >>> 0;
		let d = (d0 >>> 5) >>> 0;
		let e = (d + k3) >>> 0;
		let f = (b ^ c) >>> 0;
		let g = (f ^ e) >>> 0;
		d1 = (d1 - g) >>> 0;
		let h = (d1 << 4) >>> 0;
		let i = (h + k0) >>> 0;
		let j = (d1 + sum) >>> 0;
		let k = (d1 >>> 5) >>> 0;
		let l = (k + k1) >>> 0;
		let m = (i ^ j) >>> 0;
		let n = (m ^ l) >>> 0;
		d0 = (d0 - n) >>> 0;
		sum = (sum - DELTA) >>> 0;
	}
	return {
		d0,
		d1
	};
};

// Does not yet encrypt the last (N < 16) bytes properly.
export function encrypt(decrypted: ArrayBuffer, key: ArrayBuffer, endian?: "big" | "little"): Uint8Array {
	let little_endian = endian !== "big";
	let key_view = new DataView(key);
	let k0 = key_view.getUint32(0, little_endian);
	let k1 = key_view.getUint32(4, little_endian);
	let k2 = key_view.getUint32(8, little_endian);
	let k3 = key_view.getUint32(12, little_endian);
	let chunks = (decrypted.byteLength + 7) >> 3;
	let encrypted = new Uint8Array(chunks << 3);
	encrypted.set(new Uint8Array(decrypted), 0);
	let encrypted_view = new DataView(encrypted.buffer);
	for (let i = 0, o = 0; i < chunks; i += 1, o += 8) {
		let { e0, e1 } = encrypt_chunk(encrypted_view.getUint32(o + 0, little_endian), encrypted_view.getUint32(o + 4, little_endian), k0, k1, k2, k3);
		encrypted_view.setUint32(o + 0, e0, little_endian);
		encrypted_view.setUint32(o + 4, e1, little_endian);
	}
	return encrypted;
};

export function decrypt(encrypted: ArrayBuffer, key: ArrayBuffer, endian?: "big" | "little"): Uint8Array {
	let little_endian = endian !== "big";
	let key_view = new DataView(key);
	let k0 = key_view.getUint32(0, little_endian);
	let k1 = key_view.getUint32(4, little_endian);
	let k2 = key_view.getUint32(8, little_endian);
	let k3 = key_view.getUint32(12, little_endian);
	let decrypted = encrypted.slice(0);
	let decrypted_view = new DataView(decrypted);
	let bytes_left = decrypted.byteLength;
	let current_offset = 0;
	for (; bytes_left >= 16; bytes_left -= 8, current_offset += 8) {
		let offset = current_offset;
		let { d0, d1 } = decrypt_chunk(decrypted_view.getUint32(offset + 0, little_endian), decrypted_view.getUint32(offset + 4, little_endian), k0, k1, k2, k3);
		decrypted_view.setUint32(offset + 0, d0, little_endian);
		decrypted_view.setUint32(offset + 4, d1, little_endian);
	}
	let odd_bytes = bytes_left - 8;
	if (odd_bytes > 0) {
		let offset = current_offset + odd_bytes;
		let { d0, d1 } = decrypt_chunk(decrypted_view.getUint32(offset + 0, little_endian), decrypted_view.getUint32(offset + 4, little_endian), k0, k1, k2, k3);
		decrypted_view.setUint32(offset + 0, d0, little_endian);
		decrypted_view.setUint32(offset + 4, d1, little_endian);
	}
	if (bytes_left >= 8) {
		let offset = current_offset;
		let { d0, d1 } = decrypt_chunk(decrypted_view.getUint32(offset + 0, little_endian), decrypted_view.getUint32(offset + 4, little_endian), k0, k1, k2, k3);
		decrypted_view.setUint32(offset + 0, d0, little_endian);
		decrypted_view.setUint32(offset + 4, d1, little_endian);
	}
	return new Uint8Array(decrypted);
};
