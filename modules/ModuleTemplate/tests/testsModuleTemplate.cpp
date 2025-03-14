#include "../ModuleTemplate.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif


bool testModuleTemplate();


int main()
{
    bool res;

    std::cout << "[+] testModuleTemplate" << std::endl;
    res = testModuleTemplate();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


// test function
bool testModuleTemplate()
{

    std::unique_ptr<ModuleTemplate> moduleTemplate = std::make_unique<ModuleTemplate>();
    
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("moduleTemplate");
        splitedCmd.push_back("arg1");

        C2Message c2Message;
        C2Message c2RetMessage;
        moduleTemplate->init(splitedCmd, c2Message);
        moduleTemplate->process(c2Message, c2RetMessage);

        std::string output = "output:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("moduleTemplate");
        splitedCmd.push_back("notarg1");

        C2Message c2Message;
        C2Message c2RetMessage;
        moduleTemplate->init(splitedCmd, c2Message);
        moduleTemplate->process(c2Message, c2RetMessage);

        std::string output = "output:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        if (c2RetMessage.errorCode()) 
        {
            std::string errorMsg;
            moduleTemplate->errorCodeToMsg(c2RetMessage, errorMsg);
            std::cout << "[+] error: \n" << errorMsg << std::endl;
        } 
        else 
        {
            return false;
        }
    }

    return true;
}
