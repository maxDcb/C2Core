#include "../Powershell.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testPowershell();

int main()
{
    bool res;

    std::cout << "[+] testPowershell" << std::endl;
    res = testPowershell();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testPowershell()
{
    // std::unique_ptr<Powershell> Powershell = std::make_unique<Powershell>();
    // {
    // }

    return false;
}