#include "../MakeToken.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testMakeToken();

int main()
{
    bool res;

    std::cout << "[+] testMakeToken" << std::endl;
    res = testMakeToken();
    if(res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testMakeToken()
{
    std::unique_ptr<MakeToken> makeToken = std::make_unique<MakeToken>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("makeToken");
        splitedCmd.push_back("MARVEL\\Administrator");
        splitedCmd.push_back("P@$$w0rd!");

        C2Message c2Message;
        C2Message c2RetMessage;
        makeToken->init(splitedCmd, c2Message);
        makeToken->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("makeToken");
        splitedCmd.push_back("toto");
        splitedCmd.push_back("password");

        C2Message c2Message;
        C2Message c2RetMessage;
        makeToken->init(splitedCmd, c2Message);
        makeToken->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("makeToken");
        splitedCmd.push_back("DEV\\");
        splitedCmd.push_back("password");

        C2Message c2Message;
        C2Message c2RetMessage;
        makeToken->init(splitedCmd, c2Message);
        makeToken->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("makeToken");
        splitedCmd.push_back("DEV\\toto");

        C2Message c2Message;
        C2Message c2RetMessage;
        makeToken->init(splitedCmd, c2Message);
        makeToken->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
