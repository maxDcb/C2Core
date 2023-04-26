#include "../ChangeDirectory.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testChangeDirectory();

int main()
{
    bool res;

    std::cout << "[+] testChangeDirectory" << std::endl;
    res = testChangeDirectory();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    
    return 0;
}


bool testChangeDirectory()
{
    std::unique_ptr<ChangeDirectory> changeDirectory = std::make_unique<ChangeDirectory>();

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back("..");

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        changeDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back("C:\\Temp");

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        changeDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back("...");

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        changeDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back("C:\\");

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        changeDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
