#include "../EnumerateShares.hpp"

bool testEnumerateShares();

int main()
{
    bool res;
    std::cout << "[+] testEnumerateShares" << std::endl;
    res = testEnumerateShares();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    return !res;
}

bool testEnumerateShares()
{
    std::unique_ptr<EnumerateShares> mod = std::make_unique<EnumerateShares>();
    std::vector<std::string> cmd = {"enumerateShares"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);
    return !ret.returnvalue().empty();
}
