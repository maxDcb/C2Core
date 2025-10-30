#include "../SshExec.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<SshExec> module = std::make_unique<SshExec>();
        std::vector<std::string> cmd = {"sshExec", "-h", "127.0.0.1", "-u", "user", "-p", "pass", "-c", "whoami"};
        C2Message message;
        C2Message ret;

        int initResult = module->init(cmd, message);
        if (initResult != 0)
        {
            std::cerr << "Init should succeed for synthetic parameters" << std::endl;
        }
        module->process(message, ret);

        std::string errMsg;
        module->errorCodeToMsg(ret, errMsg);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << errMsg << std::endl;
    }

    {
        std::unique_ptr<SshExec> module = std::make_unique<SshExec>();
        std::vector<std::string> cmd = {"sshExec", "-h", "example.com", "-u", "user"};
        C2Message message;
        int initResult = module->init(cmd, message);
        if (initResult != -1)
        {
            std::cerr << "Expected failure due to missing parameters" << std::endl;
        }
        std::cout << message.returnvalue() << std::endl;
    }

    std::cout << "Finish" << std::endl;
    return 0;
}
