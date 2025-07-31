#include "../Shell.hpp"
#include <iostream>

int main()
{
    Shell shell;
    std::vector<std::string> cmd = {"shell"};
    C2Message msg, ret;
    shell.init(cmd, msg);
    shell.process(msg, ret);

    cmd = {"shell", "echo", "hello"};
    shell.init(cmd, msg);
    msg.set_cmd("echo hello");
    shell.process(msg, ret);
    bool ok = ret.returnvalue().find("hello") != std::string::npos;

    cmd = {"shell", "exit"};
    shell.init(cmd, msg);
    msg.set_cmd("exit");
    shell.process(msg, ret);

    std::cout << (ok ? "[+]" : "[-]") << " shell test" << std::endl;
    return ok ? 0 : 1;
}
