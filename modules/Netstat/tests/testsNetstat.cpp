#include "../Netstat.hpp"

bool testNetstat();

int main()
{
    bool res;
    std::cout << "[+] testNetstat" << std::endl;
    res = testNetstat();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    return !res;
}

bool testNetstat()
{
    std::unique_ptr<Netstat> mod = std::make_unique<Netstat>();
    std::vector<std::string> cmd = {"netstat"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);

    std::cout << "[+] netstat output: " << ret.returnvalue() << std::endl;

    return !ret.returnvalue().empty();
}
