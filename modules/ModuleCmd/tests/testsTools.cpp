#include <fstream>
#include <string>
#include <iostream>

#include "../Tools.hpp"


int testGetRemoteProcAddress()
{
    int pid = launchProcess("C:\\Windows\\System32\\notepad.exe");
    std::cout << "notepad pid " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    std::cout << "notepad hProcess " << hProcess << std::endl;

    Sleep(100);

    HMODULE hModule = GetRemoteModuleHandle(hProcess, "ntdll.dll");
    std::cout << "notepad ntdll.dll HMODULE " << hModule << std::endl;

    FARPROC proc = GetRemoteProcAddress (hProcess, hModule, "EtwEventWrite", 0, FALSE);
    std::cout << "notepad ntdll.dll,EtwEventWrite FARPROC " << proc << std::endl;

    TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
}


int main()
{
    testGetRemoteProcAddress();
}