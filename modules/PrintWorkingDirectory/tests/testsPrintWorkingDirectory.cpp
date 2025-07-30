#include "../PrintWorkingDirectory.hpp"

#include <filesystem>

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

    return !res;
}

bool testPrintWorkingDirectory()
{
    std::unique_ptr<PrintWorkingDirectory> printWorkingDirectory = std::make_unique<PrintWorkingDirectory>();

    std::vector<std::string> splitedCmd;
    splitedCmd.push_back("pwd");

    C2Message c2Message;
    C2Message c2RetMessage;
    printWorkingDirectory->init(splitedCmd, c2Message);
    printWorkingDirectory->process(c2Message, c2RetMessage);

    std::string expected = std::filesystem::current_path().string();
    return c2RetMessage.returnvalue() == expected;
}
