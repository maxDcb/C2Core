#include "../DcomExec.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    std::unique_ptr<DcomExec> module = std::make_unique<DcomExec>();
    std::vector<std::string> cmd = {"dcomExec", "-h", "localhost", "-c", "cmd.exe", "-a", "/c whoami"};
    C2Message message;
    C2Message ret;

    module->init(cmd, message);
    module->process(message, ret);

    std::cout << ret.returnvalue() << std::endl;
    return 0;
}
