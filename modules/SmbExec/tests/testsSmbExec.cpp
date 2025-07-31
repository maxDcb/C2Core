#include "../SmbExec.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testSmbExec();

int main()
{
    bool res;
    std::cout << "[+] testSmbExec" << std::endl;
    res = testSmbExec();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testSmbExec()
{
    std::unique_ptr<SmbExec> smbExec = std::make_unique<SmbExec>();
    std::vector<std::string> splitedCmd = {"smbExec", "127.0.0.1", "user", "pass", "echo test"};
    C2Message c2Message;
    C2Message c2RetMessage;
    smbExec->init(splitedCmd, c2Message);
    smbExec->process(c2Message, c2RetMessage);
#ifdef _WIN32
    return !c2RetMessage.returnvalue().empty();
#else
    return c2RetMessage.returnvalue().find("don't work in linux") != std::string::npos;
#endif
}
