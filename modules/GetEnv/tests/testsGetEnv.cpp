#include "../GetEnv.hpp"

bool testGetEnv();

int main()
{
    bool res;
    std::cout << "[+] testGetEnv" << std::endl;
    res = testGetEnv();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testGetEnv()
{
    std::unique_ptr<GetEnv> mod = std::make_unique<GetEnv>();
    std::vector<std::string> cmd = {"getEnv"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);
    return !ret.returnvalue().empty();
}
