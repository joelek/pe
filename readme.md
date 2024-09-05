# @joelek/pe

investigate if securom utilizes q subchannel mode-1 q/mode-2 q/mode-3 q

SecuROM 3.17.00 (Diablo II, Ground Control)
SecuROM 4.54.00 (Empire Earth)



carmageddon 2 ska ha SafeDisc 1.00.026
worms armageddon has 1.00.32
gta 2 has ?
rct has v1.06.00
	single exe => probably no encrypted segments
midtown madness has v1.07
nox has 1.40.4
the sims has 1.40.4
gta 3 has safedisc
silver
	pvd 1999-03-09
	no serial
	exe
		has cms_t and cms_d segments
		compressed with petite
	cms16.dll (compressed by pklite)
	cms32_nt.dll (compressed by petite)
	cms32_95.dll (compressed by petite)
	216 bad sectors on disc 1 (pattern (8+1)*24)
		40334-43710
		110111111111011110111100
		0xDFF7BC
outcast
	pvd 1999-05-26
	no serial
	has cms16.dll
	has cms32_95.dll
	has cms32_nt.dll
	has loader.exe (version 3.12.118? after AddD, references pklite/petite)
	has oc1.exe
	has oc2.exe
	has oc3.exe
	216 bad sectors on disc 2 (pattern (8+1)*24)
		30863-30871 (1)
		30918-30926 (1)
		31057-31065 (0)
		31155-31163 (1)
		31238-31246 (0)
		31478-31486 (1)
		31782-31790 (1)
		31921-31929 (0)
		32019-32027 (1) 32024 is just frame shifted
		32102-32110 (0)
		32342-32350 (1)
		32558-32566 (1)
		32704-32712 (0)
		32802-32810 (1)
		32885-32893 (0)
		33125-33133 (1)
		33341-33349 (1)
		33491-33499 (1)
		33795-33803 (0)
		33878-33886 (1)
		34118-34126 (0) 34124 is just frame shifted
		34334-34342 (0)
		34484-34492 (1)
		34723-34731 (1) 34724 is just frame shifted
		110101101011010111010011
		0xD6B5D3
		probably generates a list of sectors, shifts 8 of them forward by one and the ninth either +1 or max +64

	                          m  s  f     m  s  f
30871	06:51:46	41 01 01 46 49 46 00 04 51 46 05 4a	b30c 0080		6->46 (+64)		6->4 (-2)
30926	06:52:26	41 01 01 02 50 26 00 26 52 26 83 89	4780 0080		6->2 (-4)		6->26 (+32)
31065	06:54:15	41 01 01 06 52 05 00 06 54 1d 84 31	85d2 0080		15=>5 (-16)		15->1d (+8)
31163	06:55:38	41 01 01 06 52 38 00 06 d5 38 f5 cb	5eb8 0080		53->52 (-1)		55->d5 (+128)
31246	06:56:46	41 01 01 06 54 47 00 06 56 c6 40 4f	3b59 0080		46=>47 (+1)		46=>c6 (+128)
31486	06:59:61	41 01 01 06 47 61 00 06 51 61 0d 80	93ad 0080		57->47 (-16)	59->51 (-8)
31790	07:03:65	41 01 01 05 01 65 00 47 03 65 b9 31	7dce 0080
31929	07:05:54	41 01 01 07 03 5c 00 07 05 44 75 48	109c 0080
32027	07:07:02	41 01 01 07 45 02 00 07 05 02 60 21	0cf2 0080
32110	07:08:10	41 01 01 07 06 50 00 07 08 12 f1 0d	31aa 0080
32350	07:11:25	41 01 01 07 01 25 00 07 01 25 fb b1	0eb1 0080
32566	07:14:16	41 01 01 07 10 16 00 07 54 16 b1 d3	860c 0080
32712	07:16:12	41 01 01 07 14 10 00 07 16 52 19 19	0cc7 0080
32810	07:17:35	41 01 01 07 05 35 00 07 1f 35 cb 07	93ad 0080
32893	07:18:43	41 01 01 07 16 53 00 07 18 4b cd f4	85d2 0080
33133	07:21:58	41 01 01 07 1b 58 00 07 61 58 ff db	860c 0080
33349	07:24:49	41 01 01 07 62 49 00 07 26 49 ca e5	0cf2 0080
33499	07:26:49	41 01 01 27 24 49 00 03 26 49 9f 22	b2b6 0080
33803	07:30:53	41 01 01 07 28 57 00 07 30 73 d3 c9	ade4 0080
33886	07:31:61	41 01 01 03 29 61 00 27 31 61 11 40	4780 0080
34126	07:35:01	41 01 01 07 33 41 00 07 35 03 42 52	31aa 0080
34342	07:37:67	41 01 01 07 35 77 00 07 37 6f c5 90	85d2 0080
34492	07:39:67	41 01 01 07 3f 67 00 07 29 67 e6 bc	0eb1 0080
34731	07:43:06	41 01 01 06 41 06 00 87 43 06 8b 53	83bb 0080


plus och minus är xorningar
hur bestäms vilken msf-del som ska ändras?



ground control has 3.17.0 according to me+redump (June 1, 2000)
	has serial
	single exe
		contains interesting asciis @ 2582784
			.exe, .EXE
			AddD, 59JP
			00JP, 10JP
			FWS\0
			AddD
			AddD
	sierra
	has cms_t and cms_d + loads of segments
		cms_d starts with 48 x what looks like rvas
d2
	rdata and data are untouched in fixed exe
	a single table is changed in .rsrc (offsets should be absolute to )
	DIFFERENCE IN .TEXT STOPS after 16383 compressed bytes => THERE IS A LAYER OF ENCRYPTION ON THE EXE
		one byte shy of 16384 => delta or forward xor?

addition from remainder table @41e948 1e 0f 1b 6a 00 01 0d 09 00 1e 1e 00 01 31


		@00000000
	     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F       G  H  I  J  K  L  M  N
		81 EC 70 01 00 00 53 55 56 57 8B F9 33 C0 B9 DD      00 00 00 89 7C 24 18 F3 (original)
		4F 8D 56 97 00 52 F9 FA 01 BE 54 CA F2 48 46 CE      E5 96 89 F4 4B 33 EB 3A (encrypted)

	81 ^ ec ^ 22 = 4f
	ec ^ 70 ^ 11 = 8d
	70 ^ 01 ^ 27 = 56
	01 ^ 00 ^ 96 = 97	enc[3] = dec[3] ^ dec[4] ^ 0x96 (är det alltid 96? utan nästa byte?)
	00 ^ 00 ^ 00 = 00	enc[4] = dec[4] ^ dec[5] (holds)
	00 ^ 53 ^ 01 = 52   differs by ^ 0x01 sometimes, 0x0f sometimes
	53 ^ 55 ^ ff = f9
	55 ^ 56 ^ f9 = fa
	56 ^ 57 ^ 00 = 01	enc[8] = dec[8] ^ dec[9] (holds)
	57 ^ 8b ^ 62 = be
	8b ^ f9 ^ 26 = 54
	f9 ^ 33 ^ 00 = ca	enc[B] = dec[B] ^ dec[C] (holds)
	33 ^ c0 ^ 01 = f2
	c0 ^ b9 ^ 31 = 48

	b9 ^ dd ^ 22 = 46
	dd ^ 00 ^ 13 = ce



FTDB-NT97-RJVC-FGJV

oep is: 8448 (0x2100), relative in .text is 4352 (0x1100)
image base is 4194304 (0x400000)
loads dlld SysWow64\Sintfnt












00415B99 (address in cms_t) contains 16 bit value 0x2100 that is read before deobfuscation of .text segment (this is oep)

image is now different at indices 4096 (inclusive) to 4607 (inclusive) (512 bytes changed by last writeprocessmemory)
	=> this is not the same encryption









oep 02351017


		@00003984
		                 | 3990 = 285 * 14                                         |
		5E C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC (original rets) 55 8B EC 57 56 53 8B 4D 10 E3 26 8B D9 8B 7D 08
		9D F1 E2 00 FF CF E2 F1 E5 96 00 FF F3 F7 00 7B (encrypted)     C0 67 BA D0 E7 C9 AB F3 F3 C4 A0 49 52 D8 57 83

		+244@00004208 (this is around oep)
		                 | 4214 = 301 * 14                                         |
		C3 2B C2 F7 D8 1B C0 23 C3 5B C9 C3 CC CC CC CC (original rets) 8B 4C 24 08 57 53 56 8A
		9C CA 0C 71 34 52 01 0A BF 38 7E C2 40 93 1F A1 (encrypted)     AC 60 2D 55 D7 67 F1 E6

		+816@00004800
		     | 4802 = 343 * 14                         | 4816 = 344 * 14
		0A 23 45 0C C9 C3 CC CC CC CC CC CC CC CC CC CC (original rets) 8B 44 24 08 8B 4C 24 10
		28 35 2B B6 EF A5 00 FF F3 F7 00 E2 E2 00 FF 16 (encrypted)     B1 51 11 19 C7 67 27 12		(delta 812 = 2 * 7 * 29)

		+5760@00009744
	   | 9744 = 696 * 14                         | 9758 = 697 * 14
		71 40 00 8B C6 5F 5E C3 CC CC CC CC CC CC CC CC (original rets) 8D 42 FF 5B C3 8D A4 24
		95 32 70 E3 99 00 90 06 00 E2 E2 00 FF CF E2 32 (encrypted)		B4 53 A4 97 41 20 80 06		(delta 4942 = 2 * 7 * 353)

		+10608@00014592
		                             | 14602 = 1043 * 14
		__ __ __ __ __ __ __ __ __ __ CC CC CC CC CC CC (original rets) 8B 4C 24 04 F7 C1 03 00
		__ __ __ __ __ __ __ __ __ __ E2 F1 E5 96 00 46 (encrypted)     BA 5F 20 D5 18 C2 02 CF		(delta 10612 = 2 * 2 * 7 * 379, delta2 700 = 2 * 2 * 5 * 5 * 7)

		+11040@00015024
		                                   | 15036 = 1074 * 14
		__ __ __ __ __ __ __ __ CC CC CC CC CC CC CC CC (original rets) 53 8B 44 24 14 0B C0 75
		__ __ __ __ __ __ __ __ E2 00 FF CF E2 F1 E5 35 (encrypted)     D8 CE 53 27 1F AD 97 6D		(delta 266 = 2 * 7 * 19)

		+11312@00015296
		                 | 15302 = 1093 * 14                                       |
		C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC (original rets) 55 8B EC 57 56 8B 75 0C 8B 4D 10 8B 7D 08 8B C1
		0F E2 E2 00 FF CF E2 F1 E5 96 00 FF F3 F7 00 7B (encrypted)     C0 67 BA D0 BF EF 5E 1D C6 5C 8E ED 75 65 2C 4A (delta 11312 = 2 * 2 * 2 * 2 * 7 * 101)



CC CC CC CC CC CC CC CC CC CC CC CC CC CC
E2 F1 E5 96 00 FF F3 F7 00 E2 E2 00 FF CF
2E 3D 29 5A CC 33 3F 3B CC 2E 2E CC 33 03




nollorna kan vara resultatet av intermixing inom blocket (förmodligen med 32bitars inre block)
varje nolla indikerar ett jämnt antal intermixningar






ecb or ctr mode, key repeats after 7 or 14 bytes, byte index % 7 or % 14 used to intermix key?
11 non-zero bytes with zeroes inbetween, indicates one byte of data per bad sector



samma kryptering av samma data => XORKEY
att det diffar vid bounds tyder på en blockstorlek där överlappet ligger utanför repetitionen





		4 WRITEPROCESSMEMORY CALLS REPORTED (3 dll unpackers + one .text decrypt)
	THE RVAS ARE ALSO MESSED UP
	8448 is entry point for fixed exe (absolute file offset = -4096) => 55 8b ec (CORRECT)



image base is 4194304, entry point is 4202752 (0x402100)
theory

	415089 is listed as oep for v1.09b
	450760 is kernel32.readprocessmemory after securom
	replaceing game.exe makes Diablo 2 exe still load it
	has only a single user32 import (message box a)
	cms_d starts with 48*4 bytes of addresses of around 200000
	has serial
	3.17.0
	single exe
		contains interesting asciis @ 207104
			.exe, .EXE
			AddD, 59JP
			00JP, 10JP
			FWS\0
			AddD
			AddD
	90 bad sectors
		5158
		5950
		9310
		11228
		11286
		13365
		13889
		15022
		16574 (this is 6/9)
		18183
	2004 german release has http://redump.org/disc/85044/ similar sectors, different values
		149		00:01:74	41 01 00 00 40 01 00 00 03 74 2e f1	537f 8c73
		5150	01:08:50	41 01 01 21 06 50 00 05 08 50 0a 8f	8001 3237
				same as avp2 http://redump.org/disc/35861/
					149		00:01:74	41 01 00 00 40 00 00 00 03 74 84 a0	f92e 8c73
					5150	01:08:50	41 01 01 21 06 50 00 05 08 50 0a 8f	8001 3237
				same as apocalyptica http://redump.org/disc/80679/ (v4.85.01)
					149		00:01:74	41 01 00 00 40 01 00 00 03 74 2e f1	537f 8c73 (frame is wrong)
					5150	01:08:50	41 01 01 21 06 50 00 05 08 50 0a 8f	8001 3237
		5942	01:19:17	41 01 01 00 17 17 00 81 19 17 2b 76	8001 033a
		9302	02:04:02	41 01 01 02 03 02 00 02 84 02 e3 97	8001 de39
		11220	02:29:45	41 01 01 02 27 55 00 02 29 4d ab bb	8001 0553
		11278	02:30:28	41 01 01 42 28 28 00 00 30 28 52 fe	8001 338d
		13357	02:58:07	41 01 01 42 56 07 00 00 58 07 ad 82	8001 338d
		13881	03:05:06	41 01 01 03 43 06 00 03 07 06 d3 d5	8001 8c73
		15014	03:20:14	41 01 01 02 18 14 00 83 20 14 81 4a	8001 033a
		16569	03:40:69	41 01 01 43 38 69 00 01 40 69 2c ae	8001 338d
		18175	04:02:25	41 01 01 04 08 25 00 04 12 25 ea 11	8001 8e30
			the alternation seems to depend on sector number
war3
	does not contain interesting asciis
half life: blue shift
	bvd: 2001-05-28
	securom: 4.42.00
	serial: no
	publisher: sierra
	bad sectors: 99 (starts segments below)
		149,
		5150, <- occurs in empire earth
		5618, <- occurs in empire earth
		7421,
		7933,
		9273,
		10199,
		13075,
		15082, <- occurs in empire earth
		16008,
		18289
	bshift.exe
		sections: cms_t, cms_d
		pklite
arcanum
	bvd: 2001-07-12
	securom: 4.45.00
	serial: no
	bad sectors: 11
		149
		5150
		6714
		9029
		10155
		11378
		11588
		15658
		16267
		16681
		18119
	arcanum.exe
		sections: cms_t, cms_d
		pklite
empire earth has securom 4.54.00 according to redump+me (November 12, 2001)
	has serial
	has cms_t and cms_d + loads of segments
	publisher: sierra
	is listed with 11 broken sectors on redump (xor 537fx1, xor 8001x10)
		149,
		5150
		5618
		7324
		9322
		11125
		12733
		13196
		15082
		15511
		15804
	single exe
		contains interesting asciis @ 207104
			FWS\0
			10JP
			00JP
			59JP
			AddD
neverwinter nights disc 3 has securom 4.76 according to redump (June 18, 2002 pc)
	has serial
	is listed with 11 broken sectors on redump (xor 537fx1, xor 8001x10)
rct2 has SecuROM 4.83.11 according to me+redump (3 oktober 2002)
	no serial
	has cms_t and cms_d + loads of segments
	is listed with 11 broken sectors on redump (xor 537fx1, xor 8001x10)
gta vc has securom 4.84.69 (15 maj 2003 pc)
	no serial
	does not seem to have an additional exe
	has cms_t and cms_d + loads of segments
	is listed with 11 broken sectors on redump (xor 537fx1, xor 8001x10)
war3
	11 sectors
		149		00:01:74	41 01 00 00 40 01 00 00 03 74 2e f1	537f 8c73
		5150	01:08:50	41 01 01 21 06 50 00 05 08 50 0a 8f	8001 3237
		5976	01:19:51	41 01 01 05 17 51 00 21 19 51 df 99	8001 c701
		7377	01:38:27	41 01 01 01 36 37 00 01 38 2f 54 b4	8001 0553
		8163	01:48:63	41 01 01 03 46 63 00 41 48 63 89 5f	8001 fd4f
		9470	02:06:20	41 01 01 03 04 20 00 82 06 20 40 03	8001 033a
		9877	02:11:52	41 01 01 02 19 52 00 02 19 52 93 74	8001 132c
		11489	02:33:14	41 01 01 02 71 14 00 02 31 14 25 d1	8001 8c73
		11687	02:35:62	41 01 01 02 3b 62 00 02 25 62 ca 65	8001 8e30
		14080	03:07:55	41 01 01 03 0d 55 00 03 17 55 a9 20	8001 8e30
		17409	03:52:09	41 01 01 03 10 09 00 03 50 09 6e 9f	8001 8c73

ca 333 000 sectors on a cd





There're indeed different versions of SecuROM v4.8x - the ones updating earlier versions (e.g. 4.6x from D2, WC3) and the ones 4.8x from the beginning (e.g. Gothic 2) - the difference is (as I already mentioned) that even updated versions like e.g. WC3 still check subchannels only, 'cause the original cd does not contain a special physical structure to be checked.
If you check the game database correctly, you'll see e.g. D2 even with update version 1.09d protected by SecuROM v4.62.x only (-> subchannel based), MoO3 protected by SecuROM v4.84.x (-> physical cd structure).




version 1.30.10:


the previously encoded byte is used as xorkey for the current byte
	enc[k] = dec[k] ^ enc[k-1]
	dec[k] = enc[k] ^ enc[k-1]


























version 1.40.4 + 1.41.0:

.text section has been altered, purposedly calls the wrong functions
instructions call dword ptr (0xFF 0x15) indicates api call
.text is loaded at voff 4096 and has raw size of 2334720 bytes and raw offset of 4096
.rdata is loaded at voff 2338816 and has raw size of 147456 and raw offset of 2338816
image base is 4194304
Import table is at offset 138656 in .rdata.
kernel32 first thunk rva: 2338984 (this is raw offset since rdata is loaded at identical voff as raw off)

6533552 @ 2259840 should be 6533544
6533308 @ 2260456 should be 6533588
6533540 @ 2260608 should be 6533588


address - image_base = offset_in_image
6533544 - 4194304 = 2339240
(offset_in_image - kernel_32_first_Thunk_offset) / 4 = address_of_real_rva
(2339240 - 2338984) / 4 = 64 (this is the location for rva #64 K in kernel32s list of thunks)


for 1.40.4 (offset % 3 === 1)
0	0
1	1 (yes)
2	2
3	0
4	1 (yes)
5	2
6	0
7	1 (yes)
8	2
9   3

for 1.41.0 (offset % 4 !== 3)
0		1
1		1
2		1
3		0 (no)
4		1
5		1
6		1
7		0 (no)
8		1
9       1

applied to offsets starting at 0xFF 0x15


fuckup
adjusted_offset = text_offset - 2 + key;
good_index = (good_rva - image_base - first_thunk) / 4;
bad_index = (good_index + (adjusted_offset % n)) % n;
bad_rva = image_base + first_thunk + bad_index * 4


fixer:
adjusted_offset = text_offset - 2 + key;
bad_index = (bad_rva - image_base - first_thunk) / 4;
good_index = (((bad_index - (adjusted_offset % n)) % n) + n) % n;
good_rva = image_base + first_thunk + good_index * 4;










target securom up to 4.7

SecuROM v4.6

SecuROM v4.6 has been the underdog of commercial copy protection. The protection modifies a CD-ROM's q-channel in order to make a protected original distinguishable from a copy.

A set of nine locations where the Q-Channel is purposely destroyed is computed by the following function (demonstrated as python-code), using a vendor specific key.

BadSQ = 0x0
VendorKey = [0,0,0,0,0,0,0,0,0]
Seed = [0,0,0,0,0,0,0,0,0]
BadSQTable = [0,0,0,0,0,0,0,0,0]
round = 0
for a in range (0,256):
    BadSQ = BadSQ + (VendorKey[a % 9] & 0x1F) + 0x20
    for b in range (0,9):
        if (Seed[b] == a):
            BadSQTable[round] = BadSQ
            round += 1

VendorKey[], Seed[] and BadSQ are initialized to secret values.
Possible optimisations were omitted to reflect the original implementation.

The function calculates nine sector numbers; if the correspondig Q-channel is not readable at these locations, the CD is considered being original. Note that the key is always the same for all titles issued by a specific vendor, resulting in identical Q-channel patterns. Also note that every key has 134.217.727 "twinks" that will produce an identical BadSQTable.




rct3


.rdklft (aka .cms_t) Securom Code
.wpdf (aka .cms_d) Securom Data
.idata Securom's Import Table
everything else is part of the game.



grim fandango: http://redump.org/disc/70274/ 100s of securom sections 	1998-10-30
Some days later I got the original of Grim Fandango and I was disappointed
when I saw that Sony left the multi-step decryption, but added something more
to the protection.

call [KERNEL32!GetVersion]

(this is just an example, every call is changed to its original value, i.e.

the value that was in the unprotected game before Sony messed with it :-)
We have now understood it. Every time the unprotected game had to call a
system routine, or even one of its own routines, Sony saved the address
of the call into a table, and made the call point to a SecuROM routine.
When this routine is executed, it can understand where it was called
from by looking at the return value in the stack, then it patches the code
so next time the call will be made directly. At last it must give
control to the routine that was to be called, and it achieves this by a "jmp
eax" (in our example eax will contain the address of GetVersion).
Unfortunately this goes on during the whole execution of the program.
But we don't like to keep such a boring neighbour as a SecuROM part of
code, we want to kill it completely.



Securom seems to do what Safedisc does in 1.40.4+ (fuck up calls)






	SecuROM (v1.x - v3.x)
SecuROM New (v4.x: 4.0+, 4.6x, 4.7-4.83 & 4,84+)

Securom*NEW (V4.x/5.x)



The first version of SecuROM was released in 1997, initially as copy protection for PC games distributed on CD-ROM. One of the first major PC titles to utilise SecuROM was Blizzard’s Diablo II.




The latest SecuROM New revision includes "Trigger Functions" which allow the developer to program multiple and fully customizable authentication checks throughout the entire application, providing what is said to be a much stronger copy control than systems with only one check at program start. The Trigger Function toolset enables the publisher/developer to customize a unique security code for each title to prevent even title-specific cracks and Internet piracy.






diablo 2 securom v3.17: 90 sectors q-channels
xor 8001 (32769) gives non zero for 10 of them => 20 bytes (160bits)

2 bits from both MSFs are modified, original CRC-16 is XORed with 0x8001.
This range is temporary. Fixed. (LBA  5000 - 18199) or (LBA 40100 - 43799) The more disc test, the more precise.

read subchannel data
compute crc
compare to stored crc
xor these to get key
repeat a couple of times to get same key at least k times






antal felaktiga q-channels:
10 9 + 1
99  11 * 9
90  10 * 9
216 24 * 9


	securomTmp,
	securomV1, // a.k.a SecuROM OLD ((8 shifted RMSF/AMSF + 1 error) * 24 times = 216 sector error)
	securomV2, // a.k.a SecuROM NEW ((8 shifted RMSF/AMSF + 1 error) * 10 times = 90 sector error)
	securomV3_1, // a.k.a SecuROM NEW ((8 shifted RMSF/AMSF + 1 error) * 11 times = 99 sector error)
	securomV3_2, // a.k.a SecuROM NEW ((8 shifted RMSF/AMSF + 1 error) * 11 times = 99 sector error)
	securomV3_3, // a.k.a SecuROM NEW ((8 shifted RMSF/AMSF + 1 error) * 11 times = 99 sector error)
	securomV4, // a.k.a SecuROM NEW (LBA -1 + 10 random error = 11 sector error)




LBA[040169, 0x09ce9],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:44], AMSF[08:57:44], RtoW[0, 0, 0, 0]
LBA[040170, 0x09cea],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:45], AMSF[08:57:45], RtoW[0, 0, 0, 0]





040171 borde ha 8:55:46 (saknas) och kan därför inte sökas till





LBA[040171, 0x09ceb],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:47], AMSF[08:57:47], RtoW[0, 0, 0, 0]
LBA[040172, 0x09cec],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:48], AMSF[08:57:48], RtoW[0, 0, 0, 0]
LBA[040173, 0x09ced],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:49], AMSF[08:57:49], RtoW[0, 0, 0, 0]
LBA[040174, 0x09cee],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:50], AMSF[08:57:50], RtoW[0, 0, 0, 0]
LBA[040175, 0x09cef],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:51], AMSF[08:57:51], RtoW[0, 0, 0, 0]
LBA[040176, 0x09cf0],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:52], AMSF[08:57:52], RtoW[0, 0, 0, 0]
LBA[040177, 0x09cf1],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:53], AMSF[08:57:53], RtoW[0, 0, 0, 0]
LBA[040178, 0x09cf2],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:54], AMSF[08:57:54], RtoW[0, 0, 0, 0]

LBA[040179, 0x09cf3],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[00:55:54], AMSF[18:57:54], RtoW[0, 0, 0, 0]




LBA[040180, 0x09cf4],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:55], AMSF[08:57:55], RtoW[0, 0, 0, 0]
LBA[040181, 0x09cf5],  Data,      Copy NG,                  Track[01], Idx[01], RMSF[08:55:56], AMSF[08:57:56], RtoW[0, 0, 0, 0]
LBA[040170] is normal subchannel
LBA[040171] to LBA[040178] (8 sector): RMSF/AMSF is shifted
LBA[040179] is intentional error subchannel
LBA[040180] is normal subchannel
I confirmed this type is repeated 24 times.
coded this. http://www.mediafire.com/file/eq80y20l9 … or_test.7z


relative msf
absolute msf


bcd coded

1) Error in RM and error in AM (2 errors)
2) Error in RS and error in AS (2 errors)
3) Error in RF and error in AF (2 errors)





securom lagrar subchannel q med ADR läge 1 i dataregion

 8    ADR/Control (see below)
  72   Data (content depends on ADR)
  16   CRC-16-CCITT error detection code (big-endian: bytes ordered MSB, LSB)




  8    Track number (01h..99h=Track 1..99)
  8    Index number (00h=Pause, 01h..99h=Index within Track)
  24   Track relative MSF address (decreasing during Pause)
  8    Reserved (00h)
  24   Absolute MSF address
ADR=1 is required to exist in at least 9 out of 10 consecutive data sectors.

							  relative    absolute
				   adr t  i   m  s  f  _  m  s  f crc16
5150	01:08:50	41 01 01 01 06 51 00 01 08 51     30 fe	ba70 0000   + 1 frame
5151	01:08:51	41 01 01 01 06 52 00 01 08 52     ee 4f	deb1 0000   + 1 frame
5152	01:08:52	41 01 01 01 06 53 00 01 08 53     54 3f	ba70 0000   + 1 frame
5153	01:08:53	41 01 01 01 06 54 00 01 08 54     43 0c	1733 0000   + 1 frame
5154	01:08:54	41 01 01 01 06 55 00 01 08 55     f9 7c	ba70 0000   + 1 frame
5155	01:08:55	41 01 01 01 06 56 00 01 08 56     27 cd	deb1 0000   + 1 frame
5156	01:08:56	41 01 01 01 06 57 00 01 08 57     9d bd	ba70 0000   + 1 frame
5157	01:08:57	41 01 01 01 06 58 00 01 08 58     09 ab	9416 0000   + 1 frame
5158	01:08:58	41 01 01 05 06 58 00 21 08 58     89 aa	8001 c701   rm: 1=>5, am: 1=>33

5942	01:19:17	41 01 01 01 17 18 00 01 19 18     3f 61	9416 0000   + 1 frame
5943	01:19:18	41 01 01 01 17 19 00 01 19 19     85 11	ba70 0000   + 1 frame
5944	01:19:19	41 01 01 01 17 20 00 01 19 20     86 f9	03e8 0000   + 1 frame
5945	01:19:20	41 01 01 01 17 21 00 01 19 21     3c 89	ba70 0000   + 1 frame
5946	01:19:21	41 01 01 01 17 22 00 01 19 22     e2 38	deb1 0000   + 1 frame
5947	01:19:22	41 01 01 01 17 23 00 01 19 23     58 48	ba70 0000   + 1 frame
5948	01:19:23	41 01 01 01 17 24 00 01 19 24     4f 7b	1733 0000   + 1 frame
5949	01:19:24	41 01 01 01 17 25 00 01 19 25     f5 0b	ba70 0000   + 1 frame
5950	01:19:25	41 01 01 11 17 25 00 09 19 25     75 0a	8001 1edb   rm: 1=>17, am: 1=>9

9302	02:04:02	41 01 01 02 02 03 00 02 04 03     d9 e6	ba70 0000   + 1 frame
9303	02:04:03	41 01 01 02 02 04 00 02 04 04     ce d5	1733 0000   + 1 frame
9304	02:04:04	41 01 01 02 02 05 00 02 04 05     74 a5	ba70 0000   + 1 frame
9305	02:04:05	41 01 01 02 02 06 00 02 04 06     aa 14	deb1 0000   + 1 frame
9306	02:04:06	41 01 01 02 02 07 00 02 04 07     10 64	ba70 0000   + 1 frame
9307	02:04:07	41 01 01 02 02 08 00 02 04 08     84 72	9416 0000   + 1 frame
9308	02:04:08	41 01 01 02 02 09 00 02 04 09     3e 02	ba70 0000   + 1 frame
9309	02:04:09	41 01 01 02 02 10 00 02 04 10     11 3c	2f3e 0000   + 1 frame
9310	02:04:10	41 01 01 02 12 10 00 02 0c 10     91 3d	8001 132c   rs: 2=>12, as: 4=>12

11220	02:29:45	41 01 01 02 27 46 00 02 29 46     f5 0b	deb1 0000	+ 1 frame
11221	02:29:46	41 01 01 02 27 47 00 02 29 47     4f 7b	ba70 0000	+ 1 frame
11222	02:29:47	41 01 01 02 27 48 00 02 29 48     db 6d	9416 0000	+ 1 frame
11223	02:29:48	41 01 01 02 27 49 00 02 29 49     61 1d	ba70 0000	+ 1 frame
11224	02:29:49	41 01 01 02 27 50 00 02 29 50     4e 23	2f3e 0000	+ 1 frame
11225	02:29:50	41 01 01 02 27 51 00 02 29 51     f4 53	ba70 0000	+ 1 frame
11226	02:29:51	41 01 01 02 27 52 00 02 29 52     2a e2	deb1 0000	+ 1 frame
11227	02:29:52	41 01 01 02 27 53 00 02 29 53     90 92	ba70 0000	+ 1 frame
11228	02:29:53	41 01 01 02 23 53 00 02 09 53     10 93	8001 8046   rs: 39=>35, rs: 41=>9

11278	02:30:28	41 01 01 02 28 29 00 02 30 29     68 8f	ba70 0000	+ 1 frame
11279	02:30:29	41 01 01 02 28 30 00 02 30 30     47 b1	2f3e 0000	+ 1 frame
11280	02:30:30	41 01 01 02 28 31 00 02 30 31     fd c1	ba70 0000	+ 1 frame
11281	02:30:31	41 01 01 02 28 32 00 02 30 32     23 70	deb1 0000	+ 1 frame
11282	02:30:32	41 01 01 02 28 33 00 02 30 33     99 00	ba70 0000	+ 1 frame
11283	02:30:33	41 01 01 02 28 34 00 02 30 34     8e 33	1733 0000	+ 1 frame
11284	02:30:34	41 01 01 02 28 35 00 02 30 35     34 43	ba70 0000	+ 1 frame
11285	02:30:35	41 01 01 02 28 36 00 02 30 36     ea f2	deb1 0000	+ 1 frame
11286	02:30:36	41 01 01 0a 28 36 00 12 30 36     6a f3	8001 50cf   rm: 2=>10, am: 2=>18

13357	02:58:07	41 01 01 02 56 08 00 02 58 08     b9 95	9416 0000	+ 1 frame
13358	02:58:08	41 01 01 02 56 09 00 02 58 09     03 e5	ba70 0000	+ 1 frame
13359	02:58:09	41 01 01 02 56 10 00 02 58 10     2c db	2f3e 0000	+ 1 frame
13360	02:58:10	41 01 01 02 56 11 00 02 58 11     96 ab	ba70 0000	+ 1 frame
13361	02:58:11	41 01 01 02 56 12 00 02 58 12     48 1a	deb1 0000	+ 1 frame
13362	02:58:12	41 01 01 02 56 13 00 02 58 13     f2 6a	ba70 0000	+ 1 frame
13363	02:58:13	41 01 01 02 56 14 00 02 58 14     e5 59	1733 0000	+ 1 frame
13364	02:58:14	41 01 01 02 56 15 00 02 58 15     5f 29	ba70 0000	+ 1 frame
13365	02:58:15	41 01 01 0a 56 15 00 12 58 15     df 28	8001 50cf   rm: 2=>10, am: 2=>18

13881	03:05:06	41 01 01 03 03 07 00 03 05 07     e9 a4	ba70 0000	+ 1 frame
13882	03:05:07	41 01 01 03 03 08 00 03 05 08     7d b2	9416 0000	+ 1 frame
13883	03:05:08	41 01 01 03 03 09 00 03 05 09     c7 c2	ba70 0000	+ 1 frame
13884	03:05:09	41 01 01 03 03 10 00 03 05 10     e8 fc	2f3e 0000	+ 1 frame
13885	03:05:10	41 01 01 03 03 11 00 03 05 11     52 8c	ba70 0000	+ 1 frame
13886	03:05:11	41 01 01 03 03 12 00 03 05 12     8c 3d	deb1 0000	+ 1 frame
13887	03:05:12	41 01 01 03 03 13 00 03 05 13     36 4d	ba70 0000	+ 1 frame
13888	03:05:13	41 01 01 03 03 14 00 03 05 14     21 7e	1733 0000	+ 1 frame
13889	03:05:14	41 01 01 13 03 14 00 0b 05 14     a1 7f	8001 1edb   rm: 3=>19, am: 3=>11

15014	03:20:14	41 01 01 03 18 15 00 03 20 15     bb 3b	ba70 0000	+ 1 frame
15015	03:20:15	41 01 01 03 18 16 00 03 20 16     65 8a	deb1 0000	+ 1 frame
15016	03:20:16	41 01 01 03 18 17 00 03 20 17     df fa	ba70 0000	+ 1 frame
15017	03:20:17	41 01 01 03 18 18 00 03 20 18     4b ec	9416 0000	+ 1 frame
15018	03:20:18	41 01 01 03 18 19 00 03 20 19     f1 9c	ba70 0000	+ 1 frame
15019	03:20:19	41 01 01 03 18 20 00 03 20 20     f2 74	03e8 0000	+ 1 frame
15020	03:20:20	41 01 01 03 18 21 00 03 20 21     48 04	ba70 0000	+ 1 frame
15021	03:20:21	41 01 01 03 18 22 00 03 20 22     96 b5	deb1 0000	+ 1 frame
15022	03:20:22	41 01 01 13 18 22 00 0b 20 22     16 b4	8001 1edb   rm: 3=>19, am: 3=>11

16569	03:40:69	41 01 01 03 38 70 00 03 40 70     83 91	2f3e 0000	+ 1 frame
16570	03:40:70	41 01 01 03 38 71 00 03 40 71     39 e1	ba70 0000	+ 1 frame
16571	03:40:71	41 01 01 03 38 72 00 03 40 72     e7 50	deb1 0000	+ 1 frame
16572	03:40:72	41 01 01 03 38 73 00 03 40 73     5d 20	ba70 0000	+ 1 frame
16573	03:40:73	41 01 01 03 38 74 00 03 40 74     4a 13	1733 0000	+ 1 frame
16574	03:40:74	41 01 01 03 39 00 00 03 41 00     96 11	dc02 0000	+ 1 frame
16575	03:41:00	41 01 01 03 39 01 00 03 41 01     2c 61	ba70 0000	+ 1 frame
16576	03:41:01	41 01 01 03 39 02 00 03 41 02     f2 d0	deb1 0000	+ 1 frame
16577	03:41:02	41 01 01 03 39 12 00 03 41 0a     72 d1	8001 0553   rf: 2=>18, af: 2=>10

18175	04:02:25	41 01 01 04 00 26 00 04 02 26     b4 a1	deb1 0000	+ 1 frame
18176	04:02:26	41 01 01 04 00 27 00 04 02 27     0e d1	ba70 0000	+ 1 frame
18177	04:02:27	41 01 01 04 00 28 00 04 02 28     9a c7	9416 0000	+ 1 frame
18178	04:02:28	41 01 01 04 00 29 00 04 02 29     20 b7	ba70 0000	+ 1 frame
18179	04:02:29	41 01 01 04 00 30 00 04 02 30     0f 89	2f3e 0000	+ 1 frame
18180	04:02:30	41 01 01 04 00 31 00 04 02 31     b5 f9	ba70 0000	+ 1 frame
18181	04:02:31	41 01 01 04 00 32 00 04 02 32     6b 48	deb1 0000	+ 1 frame
18182	04:02:32	41 01 01 04 00 33 00 04 02 33     d1 38	ba70 0000	+ 1 frame
18183	04:02:33	41 01 01 04 01 33 00 04 82 33     51 39	8001 de39   rs: 0=>1, as: 2=>130

eight sectors with a single frame shift followed by one sector with bit additions
very uncommon to see shift in frame part



later versions (2001, d2lod) seems to only shift frames in absolute part







same changes on CDs with different patterns:

                      C/A TNO IND M   S   F   Zro aM  aS  aF  CRC      Unmd   LC1    CRC      Real   LC2
MSF: 03:08:05 Q-Data: 41  01  01  07* 06  05  00 *23  08  05  ffb8 xor b838 = 4780 | ffb8 xor ff38 = 0080
MSF: 03:08:05 Q-Data: 41  01  01  07* 06  05  00 *23  08  05  3839 xor b838 = 8001 | 3839 xor ff38 = c701

in SBI CRC is lost:

                      C/A TNO IND M   S   F   Zro aM  aS  aF  CRC      Unmd   LC1    CRC      Real   LC2
MSF: 03:08:05 Q-Data: 41  01  01  07* 06  05  00 *23  08  05  ???? xor b838 = 4780 | ???? xor ff38 = 0080
MSF: 03:08:05 Q-Data: 41  01  01  07* 06  05  00 *23  08  05  ???? xor b838 = 8001 | ???? xor ff38 = c701



F1ReB4LL
2009-04-23 20:07:06
Administrator
Offline
Registered: 2006-12-24
Posts: 3,846
CRCs are unneeded for ingame libcrypt validation, only MSFs and AMSFs are important.


The LibCrypt protection uses a Digital ID (16 bit key), which is stored in the SubChannel of a CD-ROM. Until now there have been 4 different protection schemes: LC1, LC2, LC3 & LC4





PSX/libcrypt has 32 modified sectors in 16 pairs with 5 sectors difference between each sector pair
	stores a 16 bit key


The modified sectors could be theoretically located anywhere on the disc, however, all known protected games are having them located on the same sectors:
  No.    <------- Minute=03/Normal ------->  <------- Minute=09/Backup ------->
  Bit15  14105 (03:08:05)  14110 (03:08:10)  42045 (09:20:45)  42050 (09:20:50)
  Bit14  14231 (03:09:56)  14236 (03:09:61)  42166 (09:22:16)  42171 (09:22:21)
  Bit13  14485 (03:13:10)  14490 (03:13:15)  42432 (09:25:57)  42437 (09:25:62)
  Bit12  14579 (03:14:29)  14584 (03:14:34)  42580 (09:27:55)  42585 (09:27:60)
  Bit11  14649 (03:15:24)  14654 (03:15:29)  42671 (09:28:71)  42676 (09:29:01)
  Bit10  14899 (03:18:49)  14904 (03:18:54)  42813 (09:30:63)  42818 (09:30:68)
  Bit9   15056 (03:20:56)  15061 (03:20:61)  43012 (09:33:37)  43017 (09:33:42)
  Bit8   15130 (03:21:55)  15135 (03:21:60)  43177 (09:35:52)  43182 (09:35:57)
  Bit7   15242 (03:23:17)  15247 (03:23:22)  43289 (09:37:14)  43294 (09:37:19)
  Bit6   15312 (03:24:12)  15317 (03:24:17)  43354 (09:38:04)  43359 (09:38:09)
  Bit5   15378 (03:25:03)  15383 (03:25:08)  43408 (09:38:58)  43413 (09:38:63)
  Bit4   15628 (03:28:28)  15633 (03:28:33)  43634 (09:41:59)  43639 (09:41:64)
  Bit3   15919 (03:32:19)  15924 (03:32:24)  43963 (09:46:13)  43968 (09:46:18)
  Bit2   16031 (03:33:56)  16036 (03:33:61)  44054 (09:47:29)  44059 (09:47:34)
  Bit1   16101 (03:34:51)  16106 (03:34:56)  44159 (09:48:59)  44164 (09:48:64)
  Bit0   16167 (03:35:42)  16172 (03:35:47)  44312 (09:50:62)  44317 (09:50:67)
Each bit is stored twice on Minute=03 (five sectors apart). For some reason, there is also a "backup copy" on Minute=09 (however, the libcrypt software doesn't actually support using that backup stuff, and, some discs don't have the backup at all (namely, discs with less than 10 minutes on track 1?)).
A modified sector means a "1" bit, an unmodified means a "0" bit. The 16bit keys of the existing games are always having eight "0" bits, and eight "1" bits (meaning that there are 16 modified sectors on Minute=03, and, if present, another 16 ones one Minute=09).

Example (Legacy of Kain)
Legacy of Kain (PAL) is reading the LibCrypt data during the title screen, and does then display GOT KEY!!! on TTY terminal (this, no matter if the correct 16bit key was received).
The actual protection jumps in a bit later (shortly after learning to glide, the game will hang when the first enemies appear if the key isn't okay). Thereafter, the 16bit key is kept used once and when to decrypt 800h-byte sector data via simple XORing.
The 16bit key (and some other related counters/variables) aren't stored in RAM, but rather in COP0 debug registers (which are mis-used as general-purpose storage in this case), for example, the 16bit key is stored in LSBs of the "cop0r3" register.
In particuar, the encryption is used for some of the BIGFILE.DAT folder headers:




> (0x8001^0xde39).toString(16) = 0x5e38



ccit16

Width = 16 bits
Truncated polynomial = 0x1021
Initial value = 0xFFFF


libcrypt v2 used a fixed set of sectors to modify
	each group of +5 sectors carried one bit of data
		if one of the sectors in the group were different => bit 1
		if both were missing => bit 0









Strings (said about securom 7+)

Lots of useless string obfuscation for calling kernel32 functions.

Often encrypted with Rot13.















download unsecurom:ed versions from internet (run in vm and never in win10)
check psx encryption disc sectors L1, L2, L3
	spyro 2: http://redump.org/disc/5120/
			(14105 MISSING)
			(14110 MISSING)

			(14231 MISSING)
			(14236 MISSING)

			(14485 MISSING)
			(14490 MISSING)

			(14579 MISSING)
			(14584 MISSING)

			(14649 MISSING)
			(14654 MISSING)

			(14899 MISSING)
			(14904 MISSING)

			15056	03:20:56	41 01 01 03 18 57 00 03 20 d6 bc 27	8001 bbd8	LC1 sector, no errors in data & CRC-16
			15061	03:20:61	41 01 01 03 38 61 00 03 24 61 91 a9	8001 79cd	LC1 sector, no errors in data & CRC-16

			15130	03:21:55	41 01 01 0b 19 55 00 13 21 55 14 07	8001 50cf	LC1 sector, no errors in data & CRC-16
			15135	03:21:60	41 01 01 03 19 62 00 03 21 20 5d 48	8001 8c46	LC1 sector, no errors in data & CRC-16

			15242	03:23:17	41 01 01 03 23 17 00 03 63 17 6d c6	8001 068d	LC1 sector, no errors in data & CRC-16
			15247	03:23:22	41 01 01 43 21 22 00 01 23 22 24 89	8001 338d	LC1 sector, no errors in data & CRC-16

			15312	03:24:12	41 01 01 03 02 12 00 03 20 12 49 43	8001 79cd	LC1 sector, no errors in data & CRC-16
			15317	03:24:17	41 01 01 03 22 07 00 03 24 1f 3a b1	8001 0553	LC1 sector, no errors in data & CRC-16

			15378	03:25:03	41 01 01 03 23 13 00 03 25 0b 93 c9	8001 0553	LC1 sector, no errors in data & CRC-16
			15383	03:25:08	41 01 01 0b 23 08 00 13 25 08 ce 5d	8001 50cf	LC1 sector, no errors in data & CRC-16

			(15628 MISSING)
			(15633 MISSING)

			(15919 MISSING)
			(15924 MISSING)

			16031	03:33:56	41 01 01 13 31 56 00 0b 33 56 97 ed	8001 1edb	LC1 sector, no errors in data & CRC-16
			16036	03:33:61	41 01 01 03 31 65 00 03 33 41 ba 63	8001 2d65	LC1 sector, no errors in data & CRC-16

			16101	03:34:51	41 01 01 01 32 51 00 43 34 51 d7 a9	8001 fd4f	LC1 sector, no errors in data & CRC-16
			16106	03:34:56	41 01 01 03 33 56 00 03 b4 56 c0 9a	8001 de39	LC1 sector, no errors in data & CRC-16

			16167	03:35:42	41 01 01 03 32 42 00 03 b5 42 69 e2	8001 de39	LC1 sector, no errors in data & CRC-16
			16172	03:35:47	41 01 01 03 33 07 00 03 35 45 1a 10	8001 b12b	LC1 sector, no errors in data & CRC-16

			=> 0000 0011 1110 0111 (0x03E7, matches db)









SECUROM THEORY (UP TO < V4.8):
	serial numbers are not part of securom but part of the installer created by the publisher
	securom has a few layers of protection
	first layer verifies q-channel subdata over a certain range of sectors
		it takes about 10 seconds to verify
			probably lots of reads and laser repositions
		it looks for unreadable sectors (unreadable due to intentionally bad crc16 for 9 subchannel frames)
			are shifts also considered bad sectors?
		sectors numbers are decided from vendor key and seed/title key
			is key in executable?
				yes or else any securom protected game cd would work
					can be verified by using two games with same securom version from same publisher
					it would also be interesting to check two games with same version from different publishers
					all tests should be done in virtual box windows xp with real drive
	second layer is loader (external file somewhere before securom 3.17)
		loads dlls
		loads real exe (used to be external before securom 3.17)
		real exe must be mangled in some way
		loader seems to be compressed with petite
		internal version checks command line and reads file from disk to load dll files
	third layer is dll files packed with pklite (16bit) and petite (32bit)
		for petite:
			version 1.0 released 22/5/98
			version 1.3 released 8/11/98
				includes virus/tampering checks
			version 2.2 released 15/12/99
				includes mangled imports
			clamav has open source unpacker
				mentions that it doesn't fix calls/jumps
				mentions that it unmangles the imports
				mentions that it guesses the original section, structure and entrypoint
	bad sectors to check are computed from toc?
	sectors to check are 16 bit values (<= 65535)
	numbers hidden after last section are seed numbers (dll reads ascii digits from memory)


entry point often start with push ebp; mov ebp, esp; 0x55 0x8B 0xEC
cms_t and cms_d are securom and can be removed when securom is removed
area around entry point is encrypted with title key which is read from disc subchannel q



d2, ee and gc have 51331 bytes appended
	seems to contain dlls









Game.exe is loader with Securom 3.17.00
Found by searching for AddD (stored as ascii\0 + 8)
	offset is 258048
	seems to have a hidden section of about 50kb at end
	starts exactly at AddD hint above
	references SIntf16.dll,SIntf32.dll, SIntfNT.dll
	seems to be exe
	 "address_of_entry_point": 92242,
	references pklite/petite compressor
	fixed exe does not have pklie and cms_t or cms_d but contains two exes (38kB+3500kB)
	90 bad sectors
	has serial

@258048: 64 byte header

"AddD" 3 "3.17.00\0"
4 digit chars,
16 unknown bytes
4212479 (18175 relative to image base)
4 unknown bytes
2 4270144 (75840 relative to image base) 132 3147176 1244976	(constants shared by different 3.17.00 and 4.54.00 games)

@258112:
258256 12067		(offset, length)
3149224 3147176
3149224 1245044
4214725 512
"SIntf16.dll\0" 132

@258160:
270323 17212		(offset, length)
3149224 3147176
3149224 1245044
4214725 512
"SIntf32.dll\0" 132

@258208:
287535 21840		(offset, length)
3149224 3147176
3149224 1245044
4214725 512
"SIntfNT.dll\0" 132

@258256:
(12067 bytes of data for SIntf16.dll, references pklite)

@270323:
(17212 bytes of data for SIntf32.dll, references petite)

@287535:
(21840 bytes of data for SIntfNT.dll, references petite)

258048				(original size)











War3.exe is loader with Securom 4.68.00
Found by searching for AddD (stored as ascii\0 + 8)
war3 has 54039 bytes appended
	appended bytes now contain fixed 96b header








theory: bad sectors are read and stored
the crc seems to store about 20 bytes of data = 20 bytes at end?







securom 4.42 seems to use 12 bit key








copy protections want to prevent discs from being copied to other discs as well as from being copied to hard drive
there should be parts of the protection that attempts to detect virtual drives by looking for the inaccuracies present in real drives that may not be emulated properly by a virtual drive (seek jitter etc)

(sectors below are lba + 0, not lba + 150)

check drive for disc
get drive capabilities (through inquiry?)
read toc (contains standard track and lead out track)

unsigned char ucDataBlock[20] = {
	0x00, 0x12, (18 more bytes)
	0x01, (first track)
	0x01, (last track)
	0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, (track #1)
	0x00, 0x14, 0xAA, 0x00, 0x00, 0x42, 0x10, 0x39  (lead out track)
};

read sector 16 (pvd which contains suspicious byte sequence at last 12 bytes)

FOR Diablo 2 (SecuROM 3.17.00)

unsigned char ucDataBlock[12] = {
	0x7B, 0x8C, 0x04, 0x00, (sector length 298107)
	0x7B, 0x8C, 0x04, 0x00, (sector length 298107)
	0x63, 0xCE, 0x5D, 0x55  (?)
};

FOR Ground Control (SecuROM 3.17.00)

unsigned char ucDataBlock[12] = {
	0x8E, 0xCE, 0x04, 0x00, (sector length 315022)
	0x8E, 0xCE, 0x04, 0x00, (sector length 315022)
	0x9D, 0x8A, 0x29, 0x12  (?)
};

FOR Empire Earth (SecuROM 4.54.00)

unsigned char ucDataBlock[80] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xF7, 0x8A, 0x3E, 0x31, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0xEC, 0x83, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xDA, 0x8D, 0x38, 0x46, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xA0, 0x53, 0xDE, 0x43, 0xA0, 0x53, 0xDE, 0x43,
	0x54, 0x29, 0xAF, 0x98, 0x00, 0x00, 0x00, 0x00,
	0x46, 0x03, 0x04, 0x01, (sector length with a flag)
	0x46, 0x03, 0x04, 0x00, (sector length)
	0xAF, 0x2B, 0x19, 0xE2  (?)
};



read toc (contains standard track and lead out track)
	last four bytes of PVD can be CRC of TOC because TOC can be messed up by copiers
disable eject
read random sector around 5800 with sync, header user data and edc/ecc codes using READ_CD

read random sector around 5800 (laser repositioning, cache invalidation?)

seek to sector 5800 and read subq
seek to sector 5791 (-9) and read subq
seek to sector 5793 (-7) and read subq
	(about 10 times then random small seek jumps and reads that end in different sectors)

read random sector around 9160 (laser repositioning, cache invalidation?)

seek to sector 9160 and read subq
seek to sector 9151 (-9) and read subq
seek to sector 9153 (-7) and read subq
	(about 10 times then random small seek jumps and reads that end in different sectors)

read random sector around 11078 (laser repositioning, cache invalidation?)

seek to sector 11078 and read subq
seek to sector 11069 (-9) and read subq
seek to sector 11071 (-7) and read subq
	(about 10 times then random small seek jumps and reads that end in different sectors)

read random sector around 11136 (laser repositioning, cache invalidation?)

seek to sector 11136 and read subq
seek to sector 11127 (-9) and read subq
seek to sector 11129 (-7) and read subq
	(about 10 times then random small seek jumps and reads that end in different sectors)

read random sector around 13215 (laser repositioning, cache invalidation?)

seek to sector 13215 and read subq
seek to sector 13206 (-9) and read subq
seek to sector 13208 (-7) and read subq
	(about 10 times then random small seek jumps and reads that end in different sectors)

enable eject









TODO:
compare decrypted 0x200 bytes of core against decrypted bytes to find pattern (which may be key, check for repetitions)
patent decribes number (count 6-60, mentions valid and invalid sectors) and adresses that are predetermined, addresses are key, decryption is validated before run, mentions 4-2048 bytes and the use of several encryption keys and algorithms
	mentions directly accessible blocks (seek to and query q until found)
	46x seek + 46x read subq for each range (4-5 ranges can validate or invalidate cd)
		at least one of theses seek + reads results in subcode address for the initial seek
		45 seek + read in log2 validated cd

	patent is probably for earlier version of securom or some variant of libcrypt
		especially since it mentions valid and invalid sectors being possible
		and 6-60 sectors

key is addresses of predetermined blocks already stored in executable
maybe only parts of key is validated to save validation time?
	if present in exe this is possible
are addresses in key msf adresses? 4x3=12 bytes which was seen before ()



the 9th of every sector is offset by more than 1 second, in some cases just off by +1 frame



WRITE mdf to subcode parser thing?




for iso clone and mdf clone mounted using bad software, no seeks are performed, PVD is identical but TOC differs in slight ways
for mdfcopy (cdburner xp), 4/5 seeks are performed but disc is considered a copy



the read_be command gives actual position of sector



C32: Noop.
TC32: Generate new random number in global state.
GFP32: Noop.
GNOCD32: GetDriveTypeA stuff.
GCDL32: GetDriveTypeA stuff.
RLOS32: Read sector user data if arg[2] = 0 and user data plus headers if arg[2] != 0.
MSEL32: Unknown. Sends PASS_THROUGH.
STS32: Seeks to sector in arg[0] with randomization.
TUR32: Unknown. Sends PASS_THROUGH.
LOH32: Reads current subchannel data. Validates using random number counter.
INQ32: Gathers 116bytes of information about drive. Xors some input data with key.
LD32: Locks drive eject button.
GDS32: Queries for IOCTL_STORAGE_CHECK_VERIFY. Check if drive has disc.
ADI32: Reads TOC, validates something and looks for lead out track.
ATI32: Reads TOC, validates something. Runs after PVD is read.









comparison of .text+4096 (512 bytes)


at offset 0x1100
3C 58 C0 85 31 B6 C0 71 40 00 1D C8 40 40 00 48 (encrypted)
55 8B EC 6A FF 68 C0 71 40 00 68 C8 40 40 00 64 (dumped after decryption)
55 8B EC 6A FF 68 C0 71 40 00 68 C8 40 40 00 64 (fixed)

unchanged 32bit dword at 6 and 11

at offset 0x1130
EF 1B F8 9C 40 00 5B 67 34 18 35 49 B7 CE 25 C1 (encrypted)
89 15 F8 9C 40 00 8B C8 81 E1 FF 00 00 00 89 0D (dumped after decryption)
89 15 F8 9C 40 00 8B C8 81 E1 FF 00 00 00 89 0D (fixed)

unchanged 32bit dword at 2

at offset 0x1140
f4 9c 40 00 f3 e5 cd b0 8a 5e a5 f0 9c 40 00 8e (encrypted)
f4 9c 40 00 c1 e1 08 03 ca 89 0d f0 9c 40 00 c1 (dumped after decryption)
f4 9c 40 00 c1 e1 08 03 ca 89 0d f0 9c 40 00 c1 (fixed)

unchanged 32bit dword at 0 and 10

at offset 0x1150
ED D9 51 EC 9C 40 00 56 CF C6 86 D4 A8 7B FA B4 (encrypted)
E8 10 A3 EC 9C 40 00 6A 01 E8 C8 0A 00 00 59 85 (dumped after decryption)
E8 10 A3 EC 9C 40 00 6A 01 E8 C8 0A 00 00 59 85 (fixed)

unchanged 32bit dword at 3

at offset 0x1190
00 B6 66 5F E2 41 29 78 9C 40 00 CB 75 21 5E B7 (encrypted)
00 E8 4C 1B 00 00 A3 78 9C 40 00 E8 F5 18 00 00 (dumped after decryption)
00 E8 4C 1B 00 00 A3 78 9C 40 00 E8 F5 18 00 00 (fixed)

unchanged 32bit dword at 7



all unchanged words are 0x0040NNNNN (possible operands)



0x1120+6
D2 7E E8 F2 41 00 (encrypted)
FF 15 E8 F2 41 00 (dumped after decryption)
FF 15 D8 70 40 00 (fixed)

0x1180+6
B1 F8 E8 F2 41 00 (encrypted)
FF 15 E8 F2 41 00 (dumped after decryption)
FF 15 FC 70 40 00 (fixed)

0x11B0+1
A9 DE E8 F2 41 00 (encrypted)
FF 15 E8 F2 41 00 (dumped after decryption)
FF 15 F8 70 40 00 (fixed)

0x11D0+4
45 BB E8 F2 41 00 (encrypted)
FF 15 E8 F2 41 00 (dumped after decryption)
FF 15 D4 70 40 00 (fixed)



offsets are not dword aligned, byte wise operation is performed (re indicates this as well)
it's not just securom calls to e8 f2 41 00, it's every dword that starts with 0x0040.


encrypt_16384b_at_0b_offset(
	encrypt_512b_at_4096b_offset_and_keep_calls(
		replace_FF15_api_calls_with_securom_call(
			text_segment
		),
		disc_key
	),
	encrypted_title_id
)



sequence FF 15 E8 F2 41 00 occurs after encrypted part as well (this is securom call descrambler)
