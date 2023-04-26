#include "../KerberosUseTicket.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testKerberosUseTicket();

int main()
{
    bool res;

    std::cout << "[+] testKerberosUseTicket" << std::endl;
    res = testKerberosUseTicket();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testKerberosUseTicket()
{
    // std::unique_ptr<KerberosUseTicket> KerberosUseTicket = std::make_unique<KerberosUseTicket>();
    // {
    // }

    return false;
}