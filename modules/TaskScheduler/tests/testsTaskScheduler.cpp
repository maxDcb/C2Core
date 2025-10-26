#include "../TaskScheduler.hpp"

#include <memory>
#include <vector>
#include <iostream>

int main()
{
    std::unique_ptr<TaskScheduler> module = std::make_unique<TaskScheduler>();
    std::vector<std::string> cmd = {"taskScheduler", "-c", "cmd.exe", "-a", "/c whoami"};
    C2Message message;
    C2Message ret;

    module->init(cmd, message);
    module->process(message, ret);

    std::cout << ret.returnvalue() << std::endl;
    return 0;
}
