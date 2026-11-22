#include "ListProcesses.hpp"

#include <cstring>
#include <string>
#include <array>
#include <vector>

#ifdef __linux__

#include <pwd.h>
#include <grp.h>

#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdarg>

#elif _WIN32

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <Winternl.h> 

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

#endif

#include "Common.hpp"


using namespace std;


#ifdef __linux__


namespace fs = std::filesystem;


struct ProcessInfo 
{
    std::string user;
    int pid;
    std::string state;
    long memory;
    std::string command;
};


std::string get_username(uid_t uid) 
{
    struct passwd *pw = getpwuid(uid);
    return pw ? pw->pw_name : "unknown";
}


ProcessInfo get_process_info(const std::string& pid_dir) 
{
    ProcessInfo proc_info{};
    proc_info.pid = std::stoi(pid_dir);

    // Read /proc/[PID]/status for user and state
    std::ifstream status_file("/proc/" + pid_dir + "/status");
    std::string line;
    uid_t uid = -1;

    while (std::getline(status_file, line)) 
    {
        if (line.find("Uid:") == 0) 
        {
            std::istringstream iss(line);
            std::string label;
            iss >> label >> uid; // Get the real UID
            proc_info.user = get_username(uid);
        } 
        else if (line.find("State:") == 0) 
        {
            proc_info.state = line.substr(7, 1); // Skip "State:"
        }
    }

    // Read /proc/[PID]/stat for memory usage
    std::ifstream stat_file("/proc/" + pid_dir + "/stat");
    if (stat_file) 
    {
        std::string temp;
        long rss = 0;
        for (int i = 0; i < 23; ++i) 
        {
            stat_file >> temp; // Skip to the 24th field (RSS)
        }
        stat_file >> rss; // Resident Set Size in pages
        proc_info.memory = rss * sysconf(_SC_PAGESIZE) / 1024; // Convert to KB
    }

    // Read /proc/[PID]/cmdline for command
    std::ifstream cmdline_file("/proc/" + pid_dir + "/cmdline");
    if (cmdline_file) 
    {
        std::string buffer((std::istreambuf_iterator<char>(cmdline_file)), std::istreambuf_iterator<char>());

        // Split on null character '\0'
        std::vector<std::string> args;
        std::istringstream iss(buffer);
        std::string arg;
        while (std::getline(iss, arg, '\0')) 
        {
            if (!arg.empty()) 
            {
                args.push_back(arg);
            }
        }

        // Join arguments with spaces to reconstruct the real command line
        for (size_t i = 0; i < args.size(); ++i) 
        {
            if (i > 0) 
            {
                proc_info.command += " ";
            }
            proc_info.command += args[i];
        }

    }

    return proc_info;
}


bool GetProcess(std::string& result)
{   
    std::vector<ProcessInfo> processes;

    // Iterate over /proc
    for (const auto& entry : fs::directory_iterator("/proc")) 
    {
        if (entry.is_directory()) 
        {
            std::string dirname = entry.path().filename().string();
            if (std::all_of(dirname.begin(), dirname.end(), ::isdigit)) 
            {
                try 
                {
                    processes.push_back(get_process_info(dirname));
                } 
                catch (...) 
                {
                    // Skip processes we can't access
                }
            }
        }
    }

    // Print header
    result += "USER" + std::string(16-4, ' ') + "PID" + std::string(12-3, ' ') + "STATE" + std::string(6-5, ' ') + "MEM(KB)" + std::string(12-7, ' ') + "COMMAND\n";

    // Print processes
    for (const auto& proc : processes) 
    {
        result += proc.user                     + std::string(std::max((int)(16-proc.user.size()), 1), ' ') 
                + std::to_string(proc.pid)      + std::string(std::max((int)(12-std::to_string(proc.pid).size()), 1), ' ') 
                + proc.state                    + std::string(std::max((int)(6-proc.state.size()), 1), ' ') 
                + std::to_string(proc.memory)   + std::string(std::max((int)(12-std::to_string(proc.memory).size()), 1), ' ') 
                + proc.command + "\n";
    }

    return true;
}

#elif _WIN32

#define SystemProcessInformation 5

typedef NTSTATUS (WINAPI * NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

std::string getProcessInfos(DWORD processID, std::string& processName)
{
    std::string result;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
    if (hProcess)
    {
        std::string arch = "x64";
        SYSTEM_INFO systemInfo = { 0 };
        GetNativeSystemInfo(&systemInfo);

        if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            arch = "x86";
        else
        {
            BOOL bIsWow64 = FALSE;
            IsWow64Process(hProcess, &bIsWow64);
            if (bIsWow64)
                arch = "x86";
            else
                arch = "x64";
        }

        std::string acctName;
        std::string domainName;
        HANDLE tokenHandle = nullptr;

        if (OpenProcessToken(hProcess, TOKEN_READ, &tokenHandle))
        {
            DWORD tokenUserLength = 0;
            GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, NULL, 0, &tokenUserLength);
            if (tokenUserLength > 0)
            {
                std::vector<BYTE> tokenData(tokenUserLength);
                if (GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser,
                        tokenData.data(), tokenUserLength, &tokenUserLength))
                {
                    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenData.data());
                    char userName[_MAX_PATH] = {};
                    char domain[_MAX_PATH] = {};
                    DWORD userLength = _MAX_PATH;
                    DWORD domainLength = _MAX_PATH;
                    SID_NAME_USE sidNameUse;
                    if (LookupAccountSidA(nullptr, tokenUser->User.Sid,
                            userName, &userLength, domain, &domainLength, &sidNameUse))
                    {
                        acctName = userName;
                        domainName = domain;
                    }
                }
            }
            CloseHandle(tokenHandle);
        }

        std::string account;
        if (!domainName.empty())
        {
            account += domainName;
            account += "\\";
        }
        if (!acctName.empty())
        {
            account += acctName;
            account += " ";
        }
        result += account;
        int size = max(1, (int)(30 - account.size()));
        result += std::string(size, ' ');
        result += arch;
        result += " ";
        result += processName;
        size = max(1, (int)(40 - processName.size()));
        result += std::string(size, ' ');
        result += std::to_string(processID);
        result += "\n";
    }
    else
    {
        std::string account="";
        std::string arch = "   ";
        
        result += account;
        int size = max(1, (int)(30 - account.size()));
        result += std::string(size, ' ');
        result += arch;
        result += " ";
        result += processName;
        size = max(1, (int)(40 - processName.size()));
        result += std::string(size, ' ');
        result += std::to_string(processID);
        result += "\n";
    }

    if (hProcess)
        CloseHandle(hProcess);

    return result;
}


bool GetProcess(std::string& result)
{
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    if (!ntdll)
        return false;
    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t) GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation)
        return false;

    constexpr NTSTATUS infoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
    constexpr NTSTATUS bufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
    constexpr size_t maxBufferSize = 64 * 1024 * 1024;
    std::vector<BYTE> buffer(64 * 1024);
    bool queried = false;
    size_t usedLength = 0;
    for (int attempt = 0; attempt < 10; ++attempt)
    {
        ULONG requiredLength = 0;
        const NTSTATUS status = pNtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS) SystemProcessInformation,
            buffer.data(), static_cast<ULONG>(buffer.size()), &requiredLength);
        if (status >= 0)
        {
            queried = true;
            usedLength = requiredLength > 0 && requiredLength <= buffer.size()
                ? requiredLength : buffer.size();
            break;
        }
        if (status != infoLengthMismatch && status != bufferTooSmall)
            return false;
        const size_t nextSize = (std::max)(buffer.size() * 2,
            static_cast<size_t>(requiredLength) + 64 * 1024);
        if (nextSize > maxBufferSize)
            return false;
        buffer.resize(nextSize);
    }
    if (!queried)
        return false;

    size_t offset = 0;
    while (offset + sizeof(SYSTEM_PROCESS_INFORMATION) <= usedLength)
    {        
        auto* sysproc_info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.data() + offset);
        std::string processName;
        if (sysproc_info->ImageName.Buffer && sysproc_info->ImageName.Length)
        {
            const int characters = sysproc_info->ImageName.Length / sizeof(WCHAR);
            const int bytes = WideCharToMultiByte(CP_UTF8, 0,
                sysproc_info->ImageName.Buffer, characters, nullptr, 0, nullptr, nullptr);
            if (bytes > 0)
            {
                processName.resize(bytes);
                WideCharToMultiByte(CP_UTF8, 0, sysproc_info->ImageName.Buffer,
                    characters, processName.data(), bytes, nullptr, nullptr);
            }
        }
        
        result += getProcessInfos(static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(sysproc_info->UniqueProcessId)), processName);
                
        if (!sysproc_info->NextEntryOffset)
            break;
        if (sysproc_info->NextEntryOffset > usedLength - offset)
            return false;
        offset += sysproc_info->NextEntryOffset;
    }
    
    return true;
}


#endif


constexpr std::string_view moduleName = "ps";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) ListProcesses* ListProcessesConstructor() 
{
    return new ListProcesses();
}

#else

__attribute__((visibility("default")))  ListProcesses* ListProcessesConstructor() 
{
    return new ListProcesses();
}

#endif


ListProcesses::ListProcesses()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

ListProcesses::~ListProcesses()
{
}

std::string ListProcesses::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "ListProcesses Module:\n";
    info += "List all running processes on the victim machine.\n";
    info += "Displays process ID (PID), name and owner.\n";
    info += "\nExamples:\n";
    info += "- ps\n";
#endif
    return info;
}

int ListProcesses::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() != 1 || splitedCmd[0] != std::string(moduleName))
    {
        c2Message.set_returnvalue("Usage: ps");
        return -1;
    }
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd("");
#endif

    return 0;
}

int ListProcesses::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string outCmd;
    int errorCode = 0;
    try
    {
        if (!listProcesses(outCmd) || outCmd.empty())
            errorCode = 1;
    }
    catch (...)
    {
        errorCode = 1;
    }
    if (errorCode != 0)
        outCmd.clear();

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd("");
    c2RetMessage.set_returnvalue(outCmd);
    c2RetMessage.set_errorCode(errorCode);

    return 0;
}

int ListProcesses::errorCodeToMsg(const C2Message& response, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    errorMsg.clear();
    if (response.errorCode() == 1)
        errorMsg = "Failed to enumerate processes.";
#else
    (void)response;
    (void)errorMsg;
#endif
    return 0;
}


bool ListProcesses::listProcesses(std::string& result)
{
#ifdef __linux__
    return GetProcess(result);

#elif _WIN32
    return GetProcess(result);

#else
    (void)result;
    return false;
#endif
}
