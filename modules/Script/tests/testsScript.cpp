#include "../Script.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testScript();

int main()
{
    bool res;

    std::cout << "[+] testScript" << std::endl;
    res = testScript();
    if (res)
      std::cout << "[+] Sucess" << std::endl;
    else
      std::cout << "[-] Failed" << std::endl;
    
    return 0;
}

bool testScript()
{
    std::unique_ptr<Script> script = std::make_unique<Script>();
     std::string scriptFile;
#ifdef __linux__
    scriptFile="./deepce.sh";
#elif _WIN32
    scriptFile =".\\test.bat";
#endif

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("script");
        splitedCmd.push_back(scriptFile);

        C2Message c2Message;
        C2Message c2RetMessage;
        script->init(splitedCmd, c2Message);
        script->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("script");
        splitedCmd.push_back("none");

        C2Message c2Message;
        C2Message c2RetMessage;
        script->init(splitedCmd, c2Message);
        script->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
