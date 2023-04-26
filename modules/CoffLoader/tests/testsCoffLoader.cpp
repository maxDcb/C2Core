#include "../CoffLoader.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testCoffLoader();

int main()
{
    bool res;

    std::cout << "[+] testCoffLoader" << std::endl;
    res = testCoffLoader();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testCoffLoader()
{
    std::unique_ptr<CoffLoader> coffLoader = std::make_unique<CoffLoader>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("coffLoader");
        splitedCmd.push_back(".\\dir.x64.o");
        splitedCmd.push_back("go");
        splitedCmd.push_back("Zs");
        splitedCmd.push_back("c:\\");
        splitedCmd.push_back("0");

        C2Message c2Message;
        C2Message c2RetMessage;
        coffLoader->init(splitedCmd, c2Message);
        coffLoader->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
