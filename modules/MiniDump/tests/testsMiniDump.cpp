#include "../MiniDump.hpp"

#include <fstream>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testMinidump();

int main()
{
    bool res;

    std::cout << "[+] testMinidump" << std::endl;
    res = testMinidump();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


bool testMinidump()
{
       return true;
}