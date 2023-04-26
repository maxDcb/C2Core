#include "../ListDirectory.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testListDirectory();

int main()
{
    bool res;

    std::cout << "[+] testListDirectory" << std::endl;
    res = testListDirectory();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testListDirectory()
{
    std::unique_ptr<ListDirectory> listDirectory = std::make_unique<ListDirectory>();

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        listDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back("/tmp");

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        listDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back("gsdgsg");

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        listDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back(".");

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        listDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back("C:\\");

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        listDirectory->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
