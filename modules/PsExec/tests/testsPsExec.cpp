#include "../PsExec.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testPsExec();

int main()
{
    bool res;

    std::cout << "[+] testPsExec" << std::endl;
    res = testPsExec();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testPsExec()
{
    // std::unique_ptr<PsExec> PsExec = std::make_unique<PsExec>();
    // {
    // }

    return false;
}