
let BadSQ = 5150;
let VendorKey = [123, 55, 12, 231, 19, 22, 78, 17, 95];
let Seed = [66, 192, 212, 15, 33, 17, 253, 158, 137];
let BadSQTable = [0,0,0,0,0,0,0,0,0];
let round = 0;
for (let a = 0; a < 256; a++) {
	BadSQ = BadSQ + (VendorKey[a % 9] & 0x1F) + 0x20;
	for (let b = 0; b < 9; b++) {
		if (Seed[b] == a) {
			BadSQTable[round] = BadSQ;
			round += 1;
		}
	}
}
BadSQTable.unshift(5150);
console.log({BadSQ, VendorKey, Seed, BadSQTable, round})
