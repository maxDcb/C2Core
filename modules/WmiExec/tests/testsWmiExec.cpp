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
    {
        std::unique_ptr<WmiExec> module = std::make_unique<WmiExec>();
        std::vector<std::string> cmd = {"WmiExec", "-u", "root", "root", "127.0.0.1", "cmd.exe", "-a", "/c echo ran > C:\\Users\\vuln\\Desktop\\wmiExec_test.txt"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::cout << ret.returnvalue() << std::endl;
    }
    {
        std::unique_ptr<WmiExec> module = std::make_unique<WmiExec>();
        std::vector<std::string> cmd = {"WmiExec", "-u", "root", "root", "127.0.0.1", "cmd.exe", "-a", "/c echo ran > C:\\Users\\vuln\\Desktop\\wmiExec_test2.txt"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::cout << ret.returnvalue() << std::endl;
    }
    {
        std::unique_ptr<WmiExec> module = std::make_unique<WmiExec>();
        std::vector<std::string> cmd = {"WmiExec", "-n", "127.0.0.1", "cmd.exe", "-a", "/c echo ran > C:\\Users\\vuln\\Desktop\\wmiExec_test2.txt"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::cout << ret.returnvalue() << std::endl;
    }

    return true;
}