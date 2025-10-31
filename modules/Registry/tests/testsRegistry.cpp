#include "../Registry.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    {
        std::unique_ptr<Registry> module = std::make_unique<Registry>();
        std::vector<std::string> cmd = {"registry", "set", "-h", "HKLM", "-k", "Software\\Acme", "-n", "Path", "-d", "C:/Temp"};

        C2Message message;
        C2Message ret;

        if (module->init(cmd, message) != 0)
        {
            return 1;
        }

        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << ret.returnvalue() << std::endl;
        std::cerr << err << std::endl;
    }


    return 0;
}
