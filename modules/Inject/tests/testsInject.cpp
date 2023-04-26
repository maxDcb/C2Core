#include "../Inject.hpp"
#include "../../ModuleCmd/Tools.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testInject();

int main()
{
    bool res;

    std::cout << "[+] testInject" << std::endl;
    res = testInject();
    if(res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testInject()
{
    std::unique_ptr<Inject> inject = std::make_unique<Inject>();
    std::string shellCodeFile;

    {
#ifdef _WIN32
        shellCodeFile=".\\calc.exe";

        int pid = launchProcess("C:\\Windows\\System32\\notepad.exe");
        std::cout << "notepad pid " << pid << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("inject");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(shellCodeFile);
        splitedCmd.push_back(std::to_string(pid));

        C2Message c2Message;
        C2Message c2RetMessage;
        inject->init(splitedCmd, c2Message);
        inject->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
#endif
    }

    return true;
}
