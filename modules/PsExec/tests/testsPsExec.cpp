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
    std::unique_ptr<PsExec> psExec = std::make_unique<PsExec>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("psExec");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back("c:\\windows\\system32\\notepad.exe");

        C2Message c2Message;
        C2Message c2RetMessage;
        psExec->init(splitedCmd, c2Message);
        psExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}