#include "../Evasion.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testEvasion();

int main()
{
    bool res;

    std::cout << "[+] testEvasion" << std::endl;
    res = testEvasion();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testEvasion()
{
    // std::unique_ptr<Evasion> Evasion = std::make_unique<Evasion>();
    // {
    // }

    return false;
}