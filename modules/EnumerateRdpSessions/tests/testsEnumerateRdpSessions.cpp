#include "../EnumerateRdpSessions.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<EnumerateRdpSessions> module = std::make_unique<EnumerateRdpSessions>();
        std::vector<std::string> cmd = {"enumerateRdpSessions"};

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
        std::unique_ptr<EnumerateRdpSessions> module = std::make_unique<EnumerateRdpSessions>();
        std::vector<std::string> cmd = {"enumerateRdpSessions", "-s", "127.0.0.1"};

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
        std::unique_ptr<EnumerateRdpSessions> module = std::make_unique<EnumerateRdpSessions>();
        std::vector<std::string> cmd = {"enumerateRdpSessions", "-s", "192.168.122.59"};

        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }
}
