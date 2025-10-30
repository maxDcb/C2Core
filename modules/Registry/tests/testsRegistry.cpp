#include "../Registry.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    std::unique_ptr<Registry> module = std::make_unique<Registry>();
    std::vector<std::string> cmd = {"registry", "set", "-h", "HKLM", "-k", "Software\\Acme", "-n", "Path", "-d", "C:/Temp"};

    C2Message message;
    C2Message response;

    if (module->init(cmd, message) != 0)
    {
        return 1;
    }

    module->process(message, response);

    std::string error;
    module->errorCodeToMsg(response, error);

#ifndef _WIN32
    if (response.returnvalue().find("Only supported on Windows") == std::string::npos)
    {
        return 1;
    }
#endif

    std::cout << response.returnvalue();
    if (!error.empty())
    {
        std::cerr << error;
    }

    return 0;
}
