#include "../MiniDump.hpp"

#include <fstream>
#include <vector>

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
    bool ok = true;

    {
        MiniDump module;
        std::vector<std::string> cmd = {"miniDump", "dump", "lsass.xored"};
        C2Message message;
        ok &= module.init(cmd, message) == 0;
        ok &= message.instruction() == "miniDump";
        ok &= message.cmd() == "0";
        ok &= message.outputfile() == "lsass.xored";
    }

    {
        MiniDump module;
        std::vector<std::string> cmd = {"miniDump", "dump"};
        C2Message message;
        ok &= module.init(cmd, message) == -1;
        ok &= message.returnvalue().find("MiniDump") != std::string::npos;
    }

    return ok;
}
