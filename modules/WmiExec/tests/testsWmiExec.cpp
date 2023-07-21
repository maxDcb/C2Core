#include "../WmiExec.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testWmiExec();

int main()
{
    bool res;

    std::cout << "[+] testWmiExec" << std::endl;
    res = testWmiExec();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testWmiExec()
{
    std::unique_ptr<WmiExec> wmiExec = std::make_unique<WmiExec>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("wmiExec");
        splitedCmd.push_back("127.0.0.1");
        splitedCmd.push_back("powershell.exe -NoP -NoL -sta -NonI -Exec Bypass C:\\windows\\system32\\notepad.exe");
        
        C2Message c2Message;
        C2Message c2RetMessage;
        wmiExec->init(splitedCmd, c2Message);
        wmiExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

    }

    return true;
}