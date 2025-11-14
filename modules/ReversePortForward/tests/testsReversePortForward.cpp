#include "ReversePortForward.hpp"

#include <iostream>
#include <memory>

bool testInit();
bool testInvalidArguments();
bool testErrorMessages();

int main()
{
    bool ok = true;

    std::cout << "[+] ReversePortForward tests" << std::endl;

    ok &= testInit();
    ok &= testInvalidArguments();
    ok &= testErrorMessages();

    if (ok)
        std::cout << "[+] Success" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return ok ? 0 : 1;
}

bool testInit()
{
    ReversePortForward module;
    std::vector<std::string> cmd = {"reversePortForward", "8080", "127.0.0.1", "80"};
    C2Message message;

    int rc = module.init(cmd, message);
    bool ok = rc == 0;
    ok &= message.instruction() == cmd[0];
    ok &= message.cmd() == "start";
    ok &= message.args() == "8080 127.0.0.1 80";

    return ok;
}

bool testInvalidArguments()
{
    ReversePortForward module;
    std::vector<std::string> cmd = {"reversePortForward", "invalid", "127.0.0.1", "80"};
    C2Message message;

    int rc = module.init(cmd, message);
    bool ok = rc == -1;
    ok &= !message.returnvalue().empty();

    cmd = {"reversePortForward", "8080"};
    message = C2Message();
    rc = module.init(cmd, message);
    ok &= rc == -1;
    ok &= !message.returnvalue().empty();

    return ok;
}

bool testErrorMessages()
{
    ReversePortForward module;
    std::string error;
    C2Message response;

    response.set_errorCode(1);
    module.errorCodeToMsg(response, error);
    bool ok = !error.empty();

    response.set_errorCode(2);
    module.errorCodeToMsg(response, error);
    ok &= !error.empty();

    response.set_errorCode(3);
    module.errorCodeToMsg(response, error);
    ok &= !error.empty();

    response.set_errorCode(4);
    module.errorCodeToMsg(response, error);
    ok &= !error.empty();

    return ok;
}
