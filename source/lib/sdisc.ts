import * as fs from "fs";

let mine = fs.readFileSync("./private/d2/Game.exe.stripped");
let other = fs.readFileSync("./private/d2/d2nocd_pack/Classic/1.00/Game.exe");

if (mine.length !== other.length) {
	console.log("Different lengths", mine.length, other.length);
}
let key = 0x711D791B;
let kernel32 =
	{
		"original_first_thunk_rva": 2477940,
		"time_date_stamp": 0,
		"forwarder_chain": 0,
		"name_rva": 2480652,
		"first_thunk_rva": 2338984,
		"name": "KERNEL32.dll"
	};
let user32 =
	{
		"original_first_thunk_rva": 2478372,
		"time_date_stamp": 0,
		"forwarder_chain": 0,
		"name_rva": 2481550,
		"first_thunk_rva": 2339416,
		"name": "USER32.dll"
	};
let image_base = 4194304;

let text_offsets_to_encrypt = [] as Array<number>;

let kernel32funcs = [
	{
		"type": "name",
		"rva": 2480094,
		"hint": 0,
		"name": "Sleep"
	},
	{
		"type": "name",
		"rva": 2484416,
		"hint": 0,
		"name": "GetStringTypeW"
	},
	{
		"type": "name",
		"rva": 2484434,
		"hint": 0,
		"name": "IsBadCodePtr"
	},
	{
		"type": "name",
		"rva": 2480144,
		"hint": 0,
		"name": "GlobalLock"
	},
	{
		"type": "name",
		"rva": 2480158,
		"hint": 0,
		"name": "GlobalAlloc"
	},
	{
		"type": "name",
		"rva": 2483940,
		"hint": 0,
		"name": "SetLastError"
	},
	{
		"type": "name",
		"rva": 2480172,
		"hint": 0,
		"name": "GetFileAttributesA"
	},
	{
		"type": "name",
		"rva": 2480194,
		"hint": 0,
		"name": "DeleteCriticalSection"
	},
	{
		"type": "name",
		"rva": 2480218,
		"hint": 0,
		"name": "CloseHandle"
	},
	{
		"type": "name",
		"rva": 2480232,
		"hint": 0,
		"name": "GetLastError"
	},
	{
		"type": "name",
		"rva": 2480248,
		"hint": 0,
		"name": "CreateEventA"
	},
	{
		"type": "name",
		"rva": 2480264,
		"hint": 0,
		"name": "GetDriveTypeA"
	},
	{
		"type": "name",
		"rva": 2480280,
		"hint": 0,
		"name": "GetLogicalDrives"
	},
	{
		"type": "name",
		"rva": 2480300,
		"hint": 0,
		"name": "GetDiskFreeSpaceA"
	},
	{
		"type": "name",
		"rva": 2483956,
		"hint": 0,
		"name": "TlsGetValue"
	},
	{
		"type": "name",
		"rva": 2484354,
		"hint": 0,
		"name": "EnumSystemLocalesA"
	},
	{
		"type": "name",
		"rva": 2484450,
		"hint": 0,
		"name": "GetACP"
	},
	{
		"type": "name",
		"rva": 2480418,
		"hint": 0,
		"name": "DeleteFileA"
	},
	{
		"type": "name",
		"rva": 2480432,
		"hint": 0,
		"name": "GetVersionExA"
	},
	{
		"type": "name",
		"rva": 2480448,
		"hint": 0,
		"name": "ReadFile"
	},
	{
		"type": "name",
		"rva": 2480460,
		"hint": 0,
		"name": "WaitForSingleObject"
	},
	{
		"type": "name",
		"rva": 2480482,
		"hint": 0,
		"name": "SetEvent"
	},
	{
		"type": "name",
		"rva": 2480494,
		"hint": 0,
		"name": "GetModuleFileNameA"
	},
	{
		"type": "name",
		"rva": 2480516,
		"hint": 0,
		"name": "GetFileTime"
	},
	{
		"type": "name",
		"rva": 2480530,
		"hint": 0,
		"name": "CreateFileA"
	},
	{
		"type": "name",
		"rva": 2480544,
		"hint": 0,
		"name": "FileTimeToSystemTime"
	},
	{
		"type": "name",
		"rva": 2480568,
		"hint": 0,
		"name": "FileTimeToLocalFileTime"
	},
	{
		"type": "name",
		"rva": 2480594,
		"hint": 0,
		"name": "WriteFile"
	},
	{
		"type": "name",
		"rva": 2480606,
		"hint": 0,
		"name": "FindClose"
	},
	{
		"type": "name",
		"rva": 2480618,
		"hint": 0,
		"name": "FindFirstFileA"
	},
	{
		"type": "name",
		"rva": 2480636,
		"hint": 0,
		"name": "FindNextFileA"
	},
	{
		"type": "name",
		"rva": 2483970,
		"hint": 0,
		"name": "SetUnhandledExceptionFilter"
	},
	{
		"type": "name",
		"rva": 2484000,
		"hint": 0,
		"name": "HeapSize"
	},
	{
		"type": "name",
		"rva": 2484012,
		"hint": 0,
		"name": "FlushFileBuffers"
	},
	{
		"type": "name",
		"rva": 2484032,
		"hint": 0,
		"name": "SetHandleCount"
	},
	{
		"type": "name",
		"rva": 2484050,
		"hint": 0,
		"name": "GetStdHandle"
	},
	{
		"type": "name",
		"rva": 2484066,
		"hint": 0,
		"name": "HeapDestroy"
	},
	{
		"type": "name",
		"rva": 2484080,
		"hint": 0,
		"name": "HeapCreate"
	},
	{
		"type": "name",
		"rva": 2484460,
		"hint": 0,
		"name": "GetOEMCP"
	},
	{
		"type": "name",
		"rva": 2484094,
		"hint": 0,
		"name": "VirtualFree"
	},
	{
		"type": "name",
		"rva": 2484108,
		"hint": 0,
		"name": "VirtualAlloc"
	},
	{
		"type": "name",
		"rva": 2484124,
		"hint": 0,
		"name": "IsBadWritePtr"
	},
	{
		"type": "name",
		"rva": 2484140,
		"hint": 0,
		"name": "SetStdHandle"
	},
	{
		"type": "name",
		"rva": 2484156,
		"hint": 0,
		"name": "SetEndOfFile"
	},
	{
		"type": "name",
		"rva": 2484172,
		"hint": 0,
		"name": "UnhandledExceptionFilter"
	},
	{
		"type": "name",
		"rva": 2484200,
		"hint": 0,
		"name": "FreeEnvironmentStringsA"
	},
	{
		"type": "name",
		"rva": 2484226,
		"hint": 0,
		"name": "FreeEnvironmentStringsW"
	},
	{
		"type": "name",
		"rva": 2484252,
		"hint": 0,
		"name": "GetEnvironmentStrings"
	},
	{
		"type": "name",
		"rva": 2484276,
		"hint": 0,
		"name": "GetEnvironmentStringsW"
	},
	{
		"type": "name",
		"rva": 2484302,
		"hint": 0,
		"name": "IsValidLocale"
	},
	{
		"type": "name",
		"rva": 2484318,
		"hint": 0,
		"name": "IsValidCodePage"
	},
	{
		"type": "name",
		"rva": 2484336,
		"hint": 0,
		"name": "GetLocaleInfoA"
	},
	{
		"type": "name",
		"rva": 2484398,
		"hint": 0,
		"name": "GetStringTypeA"
	},
	{
		"type": "name",
		"rva": 2483586,
		"hint": 0,
		"name": "HeapAlloc"
	},
	{
		"type": "name",
		"rva": 2484376,
		"hint": 0,
		"name": "GetUserDefaultLCID"
	},
	{
		"type": "name",
		"rva": 2483686,
		"hint": 0,
		"name": "GetSystemTime"
	},
	{
		"type": "name",
		"rva": 2480320,
		"hint": 0,
		"name": "InitializeCriticalSection"
	},
	{
		"type": "name",
		"rva": 2480348,
		"hint": 0,
		"name": "LeaveCriticalSection"
	},
	{
		"type": "name",
		"rva": 2484472,
		"hint": 0,
		"name": "GetLocaleInfoW"
	},
	{
		"type": "name",
		"rva": 2480372,
		"hint": 0,
		"name": "EnterCriticalSection"
	},
	{
		"type": "name",
		"rva": 2480396,
		"hint": 0,
		"name": "GetCurrentThreadId"
	},
	{
		"type": "name",
		"rva": 2483660,
		"hint": 0,
		"name": "GetTimeZoneInformation"
	},
	{
		"type": "name",
		"rva": 2480102,
		"hint": 0,
		"name": "SetFilePointer"
	},
	{
		"type": "name",
		"rva": 2480120,
		"hint": 0,
		"name": "GetCurrentDirectoryA"
	},
	{
		"type": "name",
		"rva": 2483598,
		"hint": 0,
		"name": "SetEnvironmentVariableA"
	},
	{
		"type": "name",
		"rva": 2483552,
		"hint": 0,
		"name": "GetCurrentProcess"
	},
	{
		"type": "name",
		"rva": 2483532,
		"hint": 0,
		"name": "TerminateProcess"
	},
	{
		"type": "name",
		"rva": 2483572,
		"hint": 0,
		"name": "HeapReAlloc"
	},
	{
		"type": "name",
		"rva": 2483498,
		"hint": 0,
		"name": "GetFullPathNameA"
	},
	{
		"type": "name",
		"rva": 2483486,
		"hint": 0,
		"name": "RtlUnwind"
	},
	{
		"type": "name",
		"rva": 2483518,
		"hint": 0,
		"name": "ExitProcess"
	},
	{
		"type": "name",
		"rva": 2483442,
		"hint": 0,
		"name": "WideCharToMultiByte"
	},
	{
		"type": "name",
		"rva": 2483418,
		"hint": 0,
		"name": "InterlockedIncrement"
	},
	{
		"type": "name",
		"rva": 2483464,
		"hint": 0,
		"name": "MultiByteToWideChar"
	},
	{
		"type": "name",
		"rva": 2483372,
		"hint": 0,
		"name": "InterlockedExchange"
	},
	{
		"type": "name",
		"rva": 2483394,
		"hint": 0,
		"name": "InterlockedDecrement"
	},
	{
		"type": "name",
		"rva": 2483354,
		"hint": 0,
		"name": "RaiseException"
	},
	{
		"type": "name",
		"rva": 2483342,
		"hint": 0,
		"name": "OpenFile"
	},
	{
		"type": "name",
		"rva": 2483332,
		"hint": 0,
		"name": "_llseek"
	},
	{
		"type": "name",
		"rva": 2483312,
		"hint": 0,
		"name": "_lclose"
	},
	{
		"type": "name",
		"rva": 2483296,
		"hint": 0,
		"name": "IsBadReadPtr"
	},
	{
		"type": "name",
		"rva": 2483322,
		"hint": 0,
		"name": "_lread"
	},
	{
		"type": "name",
		"rva": 2483264,
		"hint": 0,
		"name": "GlobalUnlock"
	},
	{
		"type": "name",
		"rva": 2483250,
		"hint": 0,
		"name": "GlobalFree"
	},
	{
		"type": "name",
		"rva": 2483280,
		"hint": 0,
		"name": "GlobalHandle"
	},
	{
		"type": "name",
		"rva": 2483220,
		"hint": 0,
		"name": "LoadLibraryA"
	},
	{
		"type": "name",
		"rva": 2483648,
		"hint": 0,
		"name": "HeapFree"
	},
	{
		"type": "name",
		"rva": 2483624,
		"hint": 0,
		"name": "SetCurrentDirectoryA"
	},
	{
		"type": "name",
		"rva": 2483236,
		"hint": 0,
		"name": "GetVersion"
	},
	{
		"type": "name",
		"rva": 2483812,
		"hint": 0,
		"name": "GetStartupInfoA"
	},
	{
		"type": "name",
		"rva": 2483928,
		"hint": 0,
		"name": "TlsAlloc"
	},
	{
		"type": "name",
		"rva": 2483910,
		"hint": 0,
		"name": "CompareStringW"
	},
	{
		"type": "name",
		"rva": 2483892,
		"hint": 0,
		"name": "CompareStringA"
	},
	{
		"type": "name",
		"rva": 2483880,
		"hint": 0,
		"name": "GetCPInfo"
	},
	{
		"type": "name",
		"rva": 2483864,
		"hint": 0,
		"name": "LCMapStringW"
	},
	{
		"type": "name",
		"rva": 2483848,
		"hint": 0,
		"name": "LCMapStringA"
	},
	{
		"type": "name",
		"rva": 2483830,
		"hint": 0,
		"name": "GetCommandLineA"
	},
	{
		"type": "name",
		"rva": 2483202,
		"hint": 0,
		"name": "GetProcAddress"
	},
	{
		"type": "name",
		"rva": 2483792,
		"hint": 0,
		"name": "GetModuleHandleA"
	},
	{
		"type": "name",
		"rva": 2483776,
		"hint": 0,
		"name": "ResumeThread"
	},
	{
		"type": "name",
		"rva": 2483762,
		"hint": 0,
		"name": "ExitThread"
	},
	{
		"type": "name",
		"rva": 2483748,
		"hint": 0,
		"name": "TlsSetValue"
	},
	{
		"type": "name",
		"rva": 2483732,
		"hint": 0,
		"name": "CreateThread"
	},
	{
		"type": "name",
		"rva": 2483718,
		"hint": 0,
		"name": "GetFileType"
	},
	{
		"type": "name",
		"rva": 2483702,
		"hint": 0,
		"name": "GetLocalTime"
	}
]
let user32funcs = [
	{
		"type": "name",
		"rva": 2481070,
		"hint": 0,
		"name": "DispatchMessageA"
	},
	{
		"type": "name",
		"rva": 2481090,
		"hint": 0,
		"name": "TranslateMessage"
	},
	{
		"type": "name",
		"rva": 2481036,
		"hint": 0,
		"name": "GetWindowLongA"
	},
	{
		"type": "name",
		"rva": 2481110,
		"hint": 0,
		"name": "GetMessageA"
	},
	{
		"type": "name",
		"rva": 2480956,
		"hint": 0,
		"name": "LoadIconA"
	},
	{
		"type": "name",
		"rva": 2480938,
		"hint": 0,
		"name": "RegisterClassA"
	},
	{
		"type": "name",
		"rva": 2480918,
		"hint": 0,
		"name": "AdjustWindowRect"
	},
	{
		"type": "name",
		"rva": 2480900,
		"hint": 0,
		"name": "CreateWindowExA"
	},
	{
		"type": "name",
		"rva": 2480886,
		"hint": 0,
		"name": "LoadCursorA"
	},
	{
		"type": "name",
		"rva": 2480874,
		"hint": 0,
		"name": "SetCursor"
	},
	{
		"type": "name",
		"rva": 2480864,
		"hint": 0,
		"name": "SetMenu"
	},
	{
		"type": "name",
		"rva": 2480850,
		"hint": 0,
		"name": "DestroyMenu"
	},
	{
		"type": "name",
		"rva": 2480834,
		"hint": 0,
		"name": "PostMessageA"
	},
	{
		"type": "name",
		"rva": 2480820,
		"hint": 0,
		"name": "SetCapture"
	},
	{
		"type": "name",
		"rva": 2480802,
		"hint": 0,
		"name": "ReleaseCapture"
	},
	{
		"type": "name",
		"rva": 2480788,
		"hint": 0,
		"name": "GetKeyState"
	},
	{
		"type": "name",
		"rva": 2480774,
		"hint": 0,
		"name": "MessageBoxA"
	},
	{
		"type": "name",
		"rva": 2480760,
		"hint": 0,
		"name": "OffsetRect"
	},
	{
		"type": "name",
		"rva": 2480742,
		"hint": 0,
		"name": "ClientToScreen"
	},
	{
		"type": "name",
		"rva": 2480726,
		"hint": 0,
		"name": "CheckMenuItem"
	},
	{
		"type": "name",
		"rva": 2480714,
		"hint": 0,
		"name": "IsIconic"
	},
	{
		"type": "name",
		"rva": 2480700,
		"hint": 0,
		"name": "ShowWindow"
	},
	{
		"type": "name",
		"rva": 2480678,
		"hint": 0,
		"name": "SetForegroundWindow"
	},
	{
		"type": "name",
		"rva": 2480666,
		"hint": 0,
		"name": "LoadMenuA"
	},
	{
		"type": "name",
		"rva": 2480968,
		"hint": 0,
		"name": "DefWindowProcA"
	},
	{
		"type": "name",
		"rva": 2481156,
		"hint": 0,
		"name": "DialogBoxParamA"
	},
	{
		"type": "name",
		"rva": 2481124,
		"hint": 0,
		"name": "WinHelpA"
	},
	{
		"type": "name",
		"rva": 2481136,
		"hint": 0,
		"name": "GetDesktopWindow"
	},
	{
		"type": "name",
		"rva": 2481200,
		"hint": 0,
		"name": "EnableMenuItem"
	},
	{
		"type": "name",
		"rva": 2481174,
		"hint": 0,
		"name": "EndDialog"
	},
	{
		"type": "name",
		"rva": 2481186,
		"hint": 0,
		"name": "DrawMenuBar"
	},
	{
		"type": "name",
		"rva": 2481520,
		"hint": 0,
		"name": "GetClientRect"
	},
	{
		"type": "name",
		"rva": 2481536,
		"hint": 0,
		"name": "BeginPaint"
	},
	{
		"type": "name",
		"rva": 2481472,
		"hint": 0,
		"name": "MoveWindow"
	},
	{
		"type": "name",
		"rva": 2481508,
		"hint": 0,
		"name": "EndPaint"
	},
	{
		"type": "name",
		"rva": 2481486,
		"hint": 0,
		"name": "AdjustWindowRectEx"
	},
	{
		"type": "name",
		"rva": 2481434,
		"hint": 0,
		"name": "SetWindowLongA"
	},
	{
		"type": "name",
		"rva": 2481464,
		"hint": 0,
		"name": "GetDC"
	},
	{
		"type": "name",
		"rva": 2481452,
		"hint": 0,
		"name": "ReleaseDC"
	},
	{
		"type": "name",
		"rva": 2481370,
		"hint": 0,
		"name": "GetWindowThreadProcessId"
	},
	{
		"type": "name",
		"rva": 2481412,
		"hint": 0,
		"name": "GetForegroundWindow"
	},
	{
		"type": "name",
		"rva": 2481398,
		"hint": 0,
		"name": "MessageBeep"
	},
	{
		"type": "name",
		"rva": 2481324,
		"hint": 0,
		"name": "UnionRect"
	},
	{
		"type": "name",
		"rva": 2481354,
		"hint": 0,
		"name": "GetCursorPos"
	},
	{
		"type": "name",
		"rva": 2481336,
		"hint": 0,
		"name": "ScreenToClient"
	},
	{
		"type": "name",
		"rva": 2481284,
		"hint": 0,
		"name": "wsprintfA"
	},
	{
		"type": "name",
		"rva": 2481310,
		"hint": 0,
		"name": "IsRectEmpty"
	},
	{
		"type": "name",
		"rva": 2481296,
		"hint": 0,
		"name": "ShowCursor"
	},
	{
		"type": "name",
		"rva": 2481232,
		"hint": 0,
		"name": "GetMenuItemID"
	},
	{
		"type": "name",
		"rva": 2481268,
		"hint": 0,
		"name": "IntersectRect"
	},
	{
		"type": "name",
		"rva": 2481248,
		"hint": 0,
		"name": "GetMenuItemCount"
	},
	{
		"type": "name",
		"rva": 2481004,
		"hint": 0,
		"name": "DestroyWindow"
	},
	{
		"type": "name",
		"rva": 2481218,
		"hint": 0,
		"name": "GetSubMenu"
	},
	{
		"type": "name",
		"rva": 2480986,
		"hint": 0,
		"name": "PostQuitMessage"
	},
	{
		"type": "name",
		"rva": 2481020,
		"hint": 0,
		"name": "GetWindowRect"
	},
	{
		"type": "name",
		"rva": 2481054,
		"hint": 0,
		"name": "PeekMessageA"
	}
]





for (let i = 4096; i < 4096 + 2334720; i++) {
	if (mine[i-2] === 0xFF && mine[i-1] === 0x15) {
		let text_offset = i-4096;
		let original = ((mine[i+3] << 24) | (mine[i+2] << 16) | (mine[i+1] << 8) | (mine[i+0] << 0)) >>> 0;
		let offset = (original - image_base) >>> 0;
		let adjusted_offset = (text_offset-2 + key) >>> 0;
		let encrypt = (adjusted_offset % 4) !== 3;
		if (offset >= kernel32.first_thunk_rva && offset < kernel32.first_thunk_rva + kernel32funcs.length*4) {
			let bad_index = (offset - kernel32.first_thunk_rva) >>> 2;
			let good_index = (((bad_index - (adjusted_offset % kernel32funcs.length)) % kernel32funcs.length) + kernel32funcs.length) % kernel32funcs.length;



/*			let bad_function = kernel32funcs[bad_index];
			let good_function = kernel32funcs[good_index]; */
			let fixed = image_base + kernel32.first_thunk_rva + good_index * 4;
			console.log("KERN32", { encrypt, text_offset, original, fixed/* , bad_function: bad_function.rva, real_function: real_function.rva */ });
		}
		if (offset >= user32.first_thunk_rva && offset < user32.first_thunk_rva + user32funcs.length*4) {
			let bad_index = (offset - user32.first_thunk_rva) >>> 2;
			let good_index = (((bad_index - (adjusted_offset % user32funcs.length)) % user32funcs.length) + user32funcs.length) % user32funcs.length;



/*			let bad_function = user32funcs[bad_index];
			let real_function = user32funcs[good_index]; */
			let fixed = image_base + user32.first_thunk_rva + good_index * 4;
			console.log("USER32", { encrypt, text_offset, original, fixed/* , bad_function: bad_function.rva, real_function: real_function.rva */ });
		}
		if (encrypt) {
			text_offsets_to_encrypt.push(text_offset);
		}
	}
}
for (let i = 0; i < Math.min(mine.length, other.length); i++) {
	if (mine[i] !== other[i]) {
		if (i >= 4096 && i < 4096 + 1470464) {
			if (mine[i-2] === 0xFF && mine[i-1] === 0x15) {
				let k = i - 0;
				let text_offset = k-4096;
				let original = (mine[k+3] << 24) | (mine[k+2] << 16) | (mine[k+1] << 8) | (mine[k+0] << 0);
				let fixed = (other[k+3] << 24) | (other[k+2] << 16) | (other[k+1] << 8) | (other[k+0] << 0);
				let adjusted_offset = (text_offset-2 + key) >>> 0;
				let decrypt = (adjusted_offset % 4) !== 3;
				if (decrypt && !text_offsets_to_encrypt.includes(text_offset)) {
					console.log("warning")
				}
				console.log("Different call at .text:" + text_offset, { k, original, fixed, adjusted_offset, decrypt });
				i += 4;
			} else if (mine[i-3] === 0xFF && mine[i-2] === 0x15) {
				let k = i - 1;
				let text_offset = k-4096;
				let original = (mine[k+3] << 24) | (mine[k+2] << 16) | (mine[k+1] << 8) | (mine[k+0] << 0);
				let fixed = (other[k+3] << 24) | (other[k+2] << 16) | (other[k+1] << 8) | (other[k+0] << 0);
				let adjusted_offset = (text_offset-2 + key) >>> 0;
				let decrypt = (adjusted_offset % 4) !== 3;
				if (decrypt && !text_offsets_to_encrypt.includes(text_offset)) {
					console.log("warning")
				}
				console.log("Different call at .text:" + text_offset, { k, original, fixed, adjusted_offset, decrypt });
				i += 3;
			} else if (mine[i-4] === 0xFF && mine[i-3] === 0x15) {
				let k = i - 2;
				let text_offset = k-4096;
				let original = (mine[k+3] << 24) | (mine[k+2] << 16) | (mine[k+1] << 8) | (mine[k+0] << 0);
				let fixed = (other[k+3] << 24) | (other[k+2] << 16) | (other[k+1] << 8) | (other[k+0] << 0);
				let adjusted_offset = (text_offset-2 + key) >>> 0;
				let decrypt = (adjusted_offset & 3) !== 3;
				if (decrypt && !text_offsets_to_encrypt.includes(text_offset)) {
					console.log("warning")
				}
				console.log("Different call at .text:" + text_offset, { k, original, fixed, adjusted_offset, decrypt });
				i += 2;
			} else if (mine[i-5] === 0xFF && mine[i-4] === 0x15) {
				let k = i - 3;
				let text_offset = k-4096;
				let original = (mine[k+3] << 24) | (mine[k+2] << 16) | (mine[k+1] << 8) | (mine[k+0] << 0);
				let fixed = (other[k+3] << 24) | (other[k+2] << 16) | (other[k+1] << 8) | (other[k+0] << 0);
				let adjusted_offset = (text_offset-2 + key) >>> 0;
				let decrypt = (adjusted_offset & 3) !== 3;
				if (decrypt && !text_offsets_to_encrypt.includes(text_offset)) {
					console.log("warning")
				}
				console.log("Different call at .text:" + text_offset, { k, original, fixed, adjusted_offset, decrypt });
				i += 1;
			} else {
				console.log("Different at .text " + i);
			}
		} else if (mine[i] === 0x00 && other[i] === 0x2B && mine[i+1] === 0x00 && other[i+1] === 0xAD) {

		} else if (mine[i-1] === 0x00 && other[i-1] === 0x2B && mine[i] === 0x00 && other[i] === 0xAD) {

		} else {
			console.log("Different at " + i);
		}
	}
}
