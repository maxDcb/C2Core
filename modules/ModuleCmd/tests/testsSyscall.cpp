#ifdef __linux__
#elif _WIN32
#include <syscall.hpp>
#endif

#include <string>
#include <iostream>


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


int main()
{
#ifdef _WIN32
    // need to be set to zero
    void *remoteBuffer = NULL;
    SIZE_T sizeToAlloc=100;
    NTSTATUS status = Sw3NtAllocateVirtualMemory_(GetCurrentProcess(), &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtAllocateVirtualMemory_" << std::endl;
        return -1;
    }

    

    std::string destinationBuffer = "test";
    std::string payload = "test";
    SIZE_T sizePayload=payload.size();
    SIZE_T NumberOfBytesWritten;
    status = Sw3NtWriteVirtualMemory_(GetCurrentProcess(), (PVOID)destinationBuffer.data(), (PVOID)payload.data(), sizePayload, &NumberOfBytesWritten);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtWriteVirtualMemory_" << std::endl;
        return -1;
    }

    payload = "toto";
    sizePayload=payload.size();
    SIZE_T NumberOfBytesRead;
    status = Sw3NtReadVirtualMemory_(GetCurrentProcess(), remoteBuffer, (PVOID)payload.data(), sizePayload, &NumberOfBytesRead);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtReadVirtualMemory_" << std::endl;
        return -1;
    }

    ULONG oldAccess;
    status = Sw3NtProtectVirtualMemory_(GetCurrentProcess(), &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtProtectVirtualMemory_" << std::endl;
        return -1;
    }

    HANDLE hThread;
    status = Sw3NtCreateThreadEx_(&hThread, 0x1FFFFF, (POBJECT_ATTRIBUTES)NULL, GetCurrentProcess(), (void*)&test, (PVOID)NULL, FALSE, 0, 0, 0, (PPS_ATTRIBUTE_LIST)NULL);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtCreateThreadEx_" << std::endl;
        return -1;
    }

    status = Sw3NtWaitForSingleObject_(hThread, false, (PLARGE_INTEGER)NULL);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtWaitForSingleObject_" << std::endl;
        return -1;
    }

    status = Sw3NtClose_(hThread);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtClose_" << std::endl;
        return -1;
    }

    DWORD dwPid = GetCurrentProcessId();
    
    HANDLE handle;
    static OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
    CLIENT_ID pid;
    pid.UniqueProcess = (HANDLE)dwPid;
    pid.UniqueThread = 0;
    status = Sw3NtOpenProcess_(&handle, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &zoa, (CLIENT_ID*)&pid);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtOpenProcess_" << std::endl;
        return -1;
    }

    HANDLE tokenHandle;
    status = Sw3NtOpenProcessToken_(handle, GENERIC_READ, &tokenHandle);
    if(status!=0)
    {
        std::cout << "Fail Sw3NtOpenProcessToken_" << std::endl;
        return -1;
    }


    // Open or create file
    HANDLE hFile = CreateFileW(
        L"C:\\Users\\Public\\ntwrite_example.txt",
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

    IO_STATUS_BLOCK ioStatus = {};
    NTSTATUS status;

    // Passing NULL ByteOffset -> use current file pointer
    IO_STATUS_BLOCK ioStatus = {};
    HANDLE Event = NULL;
    PIO_APC_ROUTINE ApcRoutine = NULL;
    PVOID ApcContext = NULL;
    PLARGE_INTEGER ByteOffset = NULL;
    PULONG Key = NULL;
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

    if (status == 0 /* STATUS_SUCCESS */) {
        std::cout << "NtWriteFile succeeded, bytes written: "
                  << ioStatus.Information << "\n";
    } else {
        std::cerr << "NtWriteFile failed, NTSTATUS = 0x"
                  << std::hex << status << "\n";
    }

    CloseHandle(hFile);

    std::cout << "Success" << std::endl;


#endif
    return 0;
}


// Sw3NtCreateProcess_ 
// Sw3NtQueueApcThread_                   
// Sw3NtResumeThread_ 
// Sw3NtAdjustPrivilegesToken_ 
// Sw3NtQueryVirtualMemory_       
