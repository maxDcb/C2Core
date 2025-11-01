#include "../SshExec.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<SshExec> module = std::make_unique<SshExec>();
        std::vector<std::string> cmd = {"sshExec", "-h", "192.168.1.21", "-u", "kali", "-p", "kali", "whoami"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string errMsg;
        module->errorCodeToMsg(ret, errMsg);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << errMsg << std::endl;
    }

    {
        std::unique_ptr<SshExec> module = std::make_unique<SshExec>();
        std::vector<std::string> cmd = {"sshExec", "-h", "192.168.1.12", "-u", "root", "-p", "root", "whoami"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string errMsg;
        module->errorCodeToMsg(ret, errMsg);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << errMsg << std::endl;
    }

    std::cout << "Finish" << std::endl;
    return 0;
}
