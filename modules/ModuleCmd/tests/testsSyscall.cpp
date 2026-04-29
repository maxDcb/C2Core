#ifdef __linux__
#elif _WIN32
#include <syscall.hpp>
#endif

#include <string>
#include <iostream>
#include <iomanip>

// Sw3NtAllocateVirtualMemory_                             
// Sw3NtWaitForSingleObject_ 
// Sw3NtCreateThreadEx_                  
// Sw3NtClose_ 
// Sw3NtWriteVirtualMemory_                     
// Sw3NtProtectVirtualMemory_ 
// Sw3NtOpenProcess_    
// Sw3NtOpenProcessToken_   
// Sw3NtReadVirtualMemory_ 


int test()
{
    std::cout << "OK from thread" << std::endl;

    return 0;
}

#ifdef _WIN32
namespace
{
    void logStep(const char* name)
    {
        std::cout << "[testsSyscall] " << name << std::endl;
    }

    void logStatus(const char* name, NTSTATUS status)
    {
        std::cout << "[testsSyscall] " << name << " -> NTSTATUS 0x"
                  << std::hex << static_cast<unsigned long>(status)
                  << std::dec << std::endl;
    }

    void logResolver(const char* name, DWORD hash)
    {
        logStep(name);
        DWORD syscallNumber = SW3_GetSyscallNumber(hash);
        PVOID syscallAddress = SW3_GetSyscallAddress(hash);
        std::cout << "[testsSyscall]   hash=0x" << std::hex << hash
                  << " number=" << std::dec << syscallNumber
                  << " address=" << syscallAddress << std::endl;
    }
}
#endif


int main()
{
#ifdef _WIN32
    logStep("preflight syscall resolver");
    logResolver("ZwAllocateVirtualMemory", 806327511);
    logResolver("ZwWriteVirtualMemory", 4080026747);
    logResolver("ZwReadVirtualMemory", 663422542);

    // need to be set to zero
    void *remoteBuffer = NULL;
    SIZE_T sizeToAlloc=100;
    logStep("calling Sw3NtAllocateVirtualMemory_");
    NTSTATUS status = Sw3NtAllocateVirtualMemory_(GetCurrentProcess(), &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    logStatus("Sw3NtAllocateVirtualMemory_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtAllocateVirtualMemory_" << std::endl;
        return -1;
    }

    

    std::string payload = "test";
    SIZE_T sizePayload = payload.size();
    SIZE_T NumberOfBytesWritten = 0;
    logStep("calling Sw3NtWriteVirtualMemory_");
    status = Sw3NtWriteVirtualMemory_(GetCurrentProcess(), remoteBuffer, (PVOID)payload.data(), sizePayload, &NumberOfBytesWritten);
    logStatus("Sw3NtWriteVirtualMemory_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtWriteVirtualMemory_" << std::endl;
        return -1;
    }

    if (NumberOfBytesWritten != sizePayload)
    {
        std::cout << "Unexpected NumberOfBytesWritten: " << NumberOfBytesWritten << std::endl;
        return -1;
    }

    std::string readBuffer(payload.size(), '\0');
    SIZE_T NumberOfBytesRead = 0;
    logStep("calling Sw3NtReadVirtualMemory_");
    status = Sw3NtReadVirtualMemory_(GetCurrentProcess(), remoteBuffer, (PVOID)readBuffer.data(), readBuffer.size(), &NumberOfBytesRead);
    logStatus("Sw3NtReadVirtualMemory_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtReadVirtualMemory_" << std::endl;
        return -1;
    }

    if (NumberOfBytesRead != readBuffer.size())
    {
        std::cout << "Unexpected NumberOfBytesRead: " << NumberOfBytesRead << std::endl;
        return -1;
    }

    if (readBuffer != payload)
    {
        std::cout << "Read content mismatch: '" << readBuffer << "'" << std::endl;
        return -1;
    }

    ULONG oldAccess;
    logStep("calling Sw3NtProtectVirtualMemory_");
    status = Sw3NtProtectVirtualMemory_(GetCurrentProcess(), &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);
    logStatus("Sw3NtProtectVirtualMemory_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtProtectVirtualMemory_" << std::endl;
        return -1;
    }

    HANDLE hThread;
    logStep("calling Sw3NtCreateThreadEx_");
    status = Sw3NtCreateThreadEx_(&hThread, 0x1FFFFF, (POBJECT_ATTRIBUTES)NULL, GetCurrentProcess(), (void*)&test, (PVOID)NULL, FALSE, 0, 0, 0, (PPS_ATTRIBUTE_LIST)NULL);
    logStatus("Sw3NtCreateThreadEx_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtCreateThreadEx_" << std::endl;
        return -1;
    }

    logStep("calling Sw3NtWaitForSingleObject_");
    status = Sw3NtWaitForSingleObject_(hThread, false, (PLARGE_INTEGER)NULL);
    logStatus("Sw3NtWaitForSingleObject_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtWaitForSingleObject_" << std::endl;
        return -1;
    }

    logStep("calling Sw3NtClose_ for thread");
    status = Sw3NtClose_(hThread);
    logStatus("Sw3NtClose_ for thread", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtClose_" << std::endl;
        return -1;
    }

    DWORD dwPid = GetCurrentProcessId();
    
    HANDLE handle;
    static OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
    CLIENT_ID pid;
    pid.UniqueProcess = (HANDLE)(ULONG_PTR)dwPid;
    pid.UniqueThread = 0;
    logStep("calling Sw3NtOpenProcess_");
    status = Sw3NtOpenProcess_(&handle, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &zoa, (CLIENT_ID*)&pid);
    logStatus("Sw3NtOpenProcess_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtOpenProcess_" << std::endl;
        return -1;
    }

    HANDLE tokenHandle;
    logStep("calling Sw3NtOpenProcessToken_");
    status = Sw3NtOpenProcessToken_(handle, GENERIC_READ, &tokenHandle);
    logStatus("Sw3NtOpenProcessToken_", status);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtOpenProcessToken_" << std::endl;
        return -1;
    }


    // Open or create file
    WCHAR tempPath[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, tempPath) == 0)
    {
        std::cerr << "GetTempPathW failed: " << GetLastError() << "\n";
        return 1;
    }

    std::wstring filePath = tempPath;
    filePath += L"ntwrite_example_";
    filePath += std::to_wstring(GetCurrentProcessId());
    filePath += L".txt";

    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFileW failed: " << GetLastError() << "\n";
        return 1;
    }

    const char* text = "Hello from NtWriteFile!\n";
    DWORD len = static_cast<DWORD>(strlen(text));

    // Passing NULL ByteOffset -> use current file pointer
    IO_STATUS_BLOCK ioStatus = {};
    HANDLE Event = NULL;
    PIO_APC_ROUTINE ApcRoutine = NULL;
    PVOID ApcContext = NULL;
    PLARGE_INTEGER ByteOffset = NULL;
    PULONG Key = NULL;
    logStep("calling Sw3NtWriteFile_");
    status = Sw3NtWriteFile_(
        hFile,
        Event,          // Event
        ApcRoutine,          // ApcRoutine
        ApcContext,          // ApcContext
        &ioStatus,
        (PVOID)text,
        len,
        ByteOffset,          // ByteOffset (NULL = append at current)
        Key           // Key
    );
    logStatus("Sw3NtWriteFile_", status);

    if (status != 0)
    {
        std::cerr << "NtWriteFile failed, NTSTATUS = 0x"
                  << std::hex << status << "\n";
        CloseHandle(hFile);
        return 1;
    }

    if (ioStatus.Information != len)
    {
        std::cerr << "NtWriteFile wrote unexpected byte count: "
                  << ioStatus.Information << "\n";
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to reopen written file for verification: " << GetLastError() << "\n";
        return 1;
    }

    std::string fileContent(len, '\0');
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileContent.data(), len, &bytesRead, nullptr))
    {
        std::cerr << "ReadFile verification failed: " << GetLastError() << "\n";
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    if (bytesRead != len || fileContent != text)
    {
        std::cerr << "NtWriteFile content mismatch\n";
        return 1;
    }

    DeleteFileW(filePath.c_str());

    logStep("calling Sw3NtClose_ for tokenHandle");
    status = Sw3NtClose_(tokenHandle);
    logStatus("Sw3NtClose_ for tokenHandle", status);
    if (status != 0)
    {
        std::cerr << "Fail Sw3NtClose_ for tokenHandle" << std::endl;
        return -1;
    }

    logStep("calling Sw3NtClose_ for process handle");
    status = Sw3NtClose_(handle);
    logStatus("Sw3NtClose_ for process handle", status);
    if (status != 0)
    {
        std::cerr << "Fail Sw3NtClose_ for process handle" << std::endl;
        return -1;
    }

    std::cout << "Success" << std::endl;


#endif
    return 0;
}


// Sw3NtCreateProcess_ 
// Sw3NtQueueApcThread_                   
// Sw3NtResumeThread_ 
// Sw3NtAdjustPrivilegesToken_ 
// Sw3NtQueryVirtualMemory_       
