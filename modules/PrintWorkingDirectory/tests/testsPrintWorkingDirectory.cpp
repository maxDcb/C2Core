#include "../PrintWorkingDirectory.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testPrintWorkingDirectory();

int main()
{
    bool res;

    std::cout << "[+] testPrintWorkingDirectory" << std::endl;
    res = testPrintWorkingDirectory();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testPrintWorkingDirectory()
{
    std::unique_ptr<PrintWorkingDirectory> printWorkingDirectory = std::make_unique<PrintWorkingDirectory>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("pwd");

        C2Message c2Message;
        C2Message c2RetMessage;
        printWorkingDirectory->init(splitedCmd, c2Message);
        printWorkingDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
