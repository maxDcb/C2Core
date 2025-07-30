#include "../Run.hpp"

#include <filesystem>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testRun();

int main()
{
    bool res;

    std::cout << "[+] testRun" << std::endl;
    res = testRun();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testRun()
{
    std::unique_ptr<Run> run = std::make_unique<Run>();
    bool ok = true;

    // ----- simple echo -----
    {
        std::vector<std::string> cmd = {"run", "echo", "hello"};
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd("echo hello");
        run->process(msg, ret);
        ok &= ret.returnvalue().find("hello") != std::string::npos;
    }

    // ----- command with spaces (split tokens) -----
    {
        std::vector<std::string> cmd = {"run", "echo", "hello", "world"};
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd("echo hello world");
        run->process(msg, ret);
        ok &= ret.returnvalue().find("hello world") != std::string::npos;
    }

    // ----- invalid command should return error text -----
    {
        std::vector<std::string> cmd = {"run", "nonexistent_command_foo"};
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd("nonexistent_command_foo");
        run->process(msg, ret);
        ok &= ret.returnvalue().empty();
    }

    // ----- missing argument -----
    {
        std::vector<std::string> cmd = {"run"};
        C2Message msg, ret;
        ok &= run->init(cmd, msg) == -1;
    }

    return ok;
}
