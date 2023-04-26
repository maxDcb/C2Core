#include "../Chisel.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testChisel();

int main()
{
    bool res;

    std::cout << "[+] testChisel" << std::endl;
    res = testChisel();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testChisel()
{
    // std::unique_ptr<Chisel> Chisel = std::make_unique<Chisel>();
    // {
    // }

    return false;
}