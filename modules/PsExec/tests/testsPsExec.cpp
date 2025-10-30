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
    std::unique_ptr<PsExec> module = std::make_unique<PsExec>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("psExec");
        splitedCmd.push_back("-n");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back(".\\TestService.exe");

        C2Message c2Message;
        C2Message ret;
        module->init(splitedCmd, c2Message);
        module->process(c2Message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("psExec");
        splitedCmd.push_back("-u");
        splitedCmd.push_back("root");
        splitedCmd.push_back("root");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back(".\\TestService.exe");

        C2Message c2Message;
        C2Message ret;
        module->init(splitedCmd, c2Message);
        module->process(c2Message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("psExec");
        splitedCmd.push_back("-u");
        splitedCmd.push_back("root");
        splitedCmd.push_back("toor");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back(".\\TestService.exe");

        C2Message c2Message;
        C2Message ret;
        module->init(splitedCmd, c2Message);
        module->process(c2Message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("psExec");
        splitedCmd.push_back("-n");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back("c:\\windows\\system32\\notepad.exe");

        C2Message c2Message;
        C2Message ret;
        module->init(splitedCmd, c2Message);
        module->process(c2Message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }



    return true;
}