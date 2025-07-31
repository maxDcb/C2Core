#include "../IpConfig.hpp"

bool testIpConfig();

int main()
{
    bool res;
    std::cout << "[+] testIpConfig" << std::endl;
    res = testIpConfig();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    return !res;
}

bool testIpConfig()
{
    std::unique_ptr<IpConfig> mod = std::make_unique<IpConfig>();
    std::vector<std::string> cmd = {"ipConfig"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);
    return !ret.returnvalue().empty();
}
