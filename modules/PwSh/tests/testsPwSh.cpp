#include "../PwSh.hpp"

#include <fstream>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testPwSh();


int main()
{
    bool res;

    std::cout << "[+] testPwSh" << std::endl;
    res = testPwSh();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


bool testPwSh()
{
    std::unique_ptr<PwSh> pwSh = std::make_unique<PwSh>();

    // PowerShellRunner DLL
    {
        
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("pwSh");
            splitedCmd.push_back("init");
            splitedCmd.push_back(".\\rdm.dll");
            splitedCmd.push_back("rdm.rdm");

            C2Message c2Message;
            C2Message c2RetMessage;
            pwSh->init(splitedCmd, c2Message);
            pwSh->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;
        }
        {
            std::string testString = "test";

            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("pwSh");
            splitedCmd.push_back("run");
            splitedCmd.push_back("echo");
            splitedCmd.push_back(testString);
            splitedCmd.push_back("|");
            splitedCmd.push_back("write-output");

            C2Message c2Message;
            C2Message c2RetMessage;
            pwSh->init(splitedCmd, c2Message);
            pwSh->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;
        }
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("pwSh");
            splitedCmd.push_back("run");
            splitedCmd.push_back("whoami /priv");
            splitedCmd.push_back("|");
            splitedCmd.push_back("write-output");

            C2Message c2Message;
            C2Message c2RetMessage;
            pwSh->init(splitedCmd, c2Message);
            pwSh->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;
        }
    }

    return true;
}