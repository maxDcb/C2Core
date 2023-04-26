#include "../SpawnAs.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testSpawnAs();

int main()
{
    bool res;

    std::cout << "[+] testSpawnAs" << std::endl;
    res = testSpawnAs();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testSpawnAs()
{
    // std::unique_ptr<SpawnAs> SpawnAs = std::make_unique<SpawnAs>();
    // {
    // }

    return false;
}