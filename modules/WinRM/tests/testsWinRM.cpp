#include "../WinRM.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<WinRM> module = std::make_unique<WinRM>();
        std::vector<std::string> cmd = {"winrm", "-n", "http://localhost:5985/wsman", "whoami.exe",  "/all"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
    {
        std::unique_ptr<WinRM> module = std::make_unique<WinRM>();
        std::vector<std::string> cmd = {"winrm", "-n", "http://localhost:5985/wsman", "dir", "C:\\"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
    {
        std::unique_ptr<WinRM> module = std::make_unique<WinRM>();
        std::vector<std::string> cmd = {"winrm", "-u", "root", "root", "http://localhost:5985/wsman", "dir", "C:\\"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }

    return 0;
}
