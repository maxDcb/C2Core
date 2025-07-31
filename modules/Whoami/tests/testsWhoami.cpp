#include "../Whoami.hpp"

bool testWhoami();

int main()
{
    bool res;
    std::cout << "[+] testWhoami" << std::endl;
    res = testWhoami();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    return !res;
}

bool testWhoami()
{
    std::unique_ptr<Whoami> mod = std::make_unique<Whoami>();
    std::vector<std::string> cmd = {"whoami"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);
    return !ret.returnvalue().empty();
}
