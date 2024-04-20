#include <fstream>
#include <string>
#include <iostream>
#include <cassert>

#include "../Tools.hpp"


int testGetRemoteProcAddress()
{
#ifdef _WIN32
    int pid = launchProcess("C:\\Windows\\System32\\notepad.exe");
    std::cout << "notepad pid " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    std::cout << "notepad hProcess " << hProcess << std::endl;

    assert(hProcess != 0);

    Sleep(100);

    HMODULE hModule = GetRemoteModuleHandle(hProcess, "ntdll.dll");
    std::cout << "notepad ntdll.dll HMODULE " << hModule << std::endl;

    assert(hModule != 0);

    FARPROC proc = GetRemoteProcAddress (hProcess, hModule, "EtwEventWrite", 0, FALSE);
    std::cout << "notepad ntdll.dll,EtwEventWrite FARPROC " << proc << std::endl;

    assert(proc != 0);

    TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
#endif

    return 0;
}


int main()
{
    testGetRemoteProcAddress();
}