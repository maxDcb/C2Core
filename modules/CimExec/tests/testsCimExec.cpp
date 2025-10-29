#include "../CimExec.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<CimExec> module = std::make_unique<CimExec>();
        std::vector<std::string> cmd = {"cimExec", "-h", "localhost", "-u", "root", "-p", "root", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\vuln\\Desktop\\ts_test2.txt"};
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
        std::unique_ptr<CimExec> module = std::make_unique<CimExec>();
        std::vector<std::string> cmd = {"cimExec", "-h", "localhost", "-c", "cmd.exe", "-a", "/c whoami"};
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
        std::unique_ptr<CimExec> module = std::make_unique<CimExec>();
        std::vector<std::string> cmd = {"cimExec", "-h", "localhost", "-u", "root", "-p", "toor", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\vuln\\Desktop\\ts_test2.txt"};
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

