#include "../StealToken.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testStealToken();

int main()
{
    bool res;

    std::cout << "[+] testStealToken" << std::endl;
    res = testStealToken();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testStealToken()
{
    std::unique_ptr<StealToken> stealToken = std::make_unique<StealToken>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("stealToken");
        splitedCmd.push_back("44");

        C2Message c2Message;
        C2Message c2RetMessage;
        stealToken->init(splitedCmd, c2Message);
        stealToken->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
