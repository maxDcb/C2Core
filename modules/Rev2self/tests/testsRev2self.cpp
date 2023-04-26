#include "../Rev2self.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testRev2self();

int main()
{
    bool res;

    std::cout << "[+] testRev2self" << std::endl;
    res = testRev2self();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testRev2self()
{
    std::unique_ptr<Rev2self> rev2self = std::make_unique<Rev2self>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("rev2self");

        C2Message c2Message;
        C2Message c2RetMessage;
        rev2self->init(splitedCmd, c2Message);
        rev2self->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
