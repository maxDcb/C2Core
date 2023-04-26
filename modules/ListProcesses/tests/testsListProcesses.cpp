#include "../ListProcesses.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testListProcesses();

int main()
{
    bool res;

    std::cout << "[+] testListProcesses" << std::endl;
    res = testListProcesses();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testListProcesses()
{
    std::unique_ptr<ListProcesses> listProcesses = std::make_unique<ListProcesses>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ps");

        C2Message c2Message;
        C2Message c2RetMessage;
        listProcesses->init(splitedCmd, c2Message);
        listProcesses->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
