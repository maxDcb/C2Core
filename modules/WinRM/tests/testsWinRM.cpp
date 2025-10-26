#include "../WinRM.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    std::unique_ptr<WinRM> module = std::make_unique<WinRM>();
    std::vector<std::string> cmd = {"winrm", "-e", "localhost", "-c", "cmd.exe", "-a", "/c hostname"};
    C2Message message;
    C2Message ret;

    module->init(cmd, message);
    module->process(message, ret);

    std::cout << ret.returnvalue() << std::endl;
    return 0;
}
