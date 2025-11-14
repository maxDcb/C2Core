#include "../RawWinRm.hpp"

#include <iostream>
#include <memory>
#include <vector>

bool testUsage();

int main()
{
    bool ok = true;

    std::cout << "[+] testRawWinRm" << std::endl;
    ok &= testUsage();

    if(ok)
        std::cout << "[+] Success" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return ok ? 0 : 1;
}

bool testUsage()
{
    std::unique_ptr<RawWinRm> module = std::make_unique<RawWinRm>();
    std::vector<std::string> cmd = {"rawWinRm", "http://host:5985/wsman", "DOMAIN\\user", "--hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ipconfig"};
    C2Message msg;
    C2Message ret;

    if(module->init(cmd, msg) != 0)
    {
        return false;
    }

    if(std::string(msg.data()).find("ipconfig") == std::string::npos)
    {
        return false;
    }

    std::vector<std::string> bad = {"rawWinRm", "http://host", "user"};
    C2Message badMsg;
    if(module->init(bad, badMsg) != -1)
    {
        return false;
    }

    module->process(msg, ret);
    if(ret.errorCode() == 0 && ret.returnvalue().empty())
    {
        return false;
    }

    std::string error;
    module->errorCodeToMsg(ret, error);

    return true;
}
