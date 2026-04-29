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

    return !res;
}

bool testRun()
{
    std::unique_ptr<Run> run = std::make_unique<Run>();
    bool ok = true;

    // ----- simple echo -----
    {
#ifdef _WIN32
        std::vector<std::string> cmd = {"run", "cmd.exe", "/c", "echo", "hello"};
        const std::string shellCmd = "cmd.exe /c echo hello";
#else
        std::vector<std::string> cmd = {"run", "echo", "hello"};
        const std::string shellCmd = "echo hello";
#endif
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd(shellCmd);
        run->process(msg, ret);
        ok &= ret.returnvalue().find("hello") != std::string::npos;
    }

    // ----- command with spaces (split tokens) -----
    {
#ifdef _WIN32
        std::vector<std::string> cmd = {"run", "cmd.exe", "/c", "echo", "hello", "world"};
        const std::string shellCmd = "cmd.exe /c echo hello world";
#else
        std::vector<std::string> cmd = {"run", "echo", "hello", "world"};
        const std::string shellCmd = "echo hello world";
#endif
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd(shellCmd);
        run->process(msg, ret);
        ok &= ret.returnvalue().find("hello world") != std::string::npos;
    }

    // ----- invalid command should return error text -----
    {
#ifdef _WIN32
        std::vector<std::string> cmd = {"run", "cmd.exe", "/c", "nonexistent_command_foo"};
        const std::string shellCmd = "cmd.exe /c nonexistent_command_foo";
#else
        std::vector<std::string> cmd = {"run", "nonexistent_command_foo"};
        const std::string shellCmd = "nonexistent_command_foo";
#endif
        C2Message msg, ret;
        run->init(cmd, msg);
        msg.set_cmd(shellCmd);
        run->process(msg, ret);
        ok &= !ret.returnvalue().empty();
    }

    // ----- missing argument -----
    {
        std::vector<std::string> cmd = {"run"};
        C2Message msg, ret;
        ok &= run->init(cmd, msg) == -1;
    }

    return ok;
}
