#include "../Tree.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testTree();

int main()
{
    bool res;

    std::cout << "[+] testTree" << std::endl;
    res = testTree();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testTree()
{
    std::unique_ptr<Tree> tree = std::make_unique<Tree>();

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("tree");

        C2Message c2Message;
        C2Message c2RetMessage;
        tree->init(splitedCmd, c2Message);
        tree->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("tree");
        splitedCmd.push_back("C:\\Users");

        C2Message c2Message;
        C2Message c2RetMessage;
        tree->init(splitedCmd, c2Message);
        tree->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("tree");
        splitedCmd.push_back(".");

        C2Message c2Message;
        C2Message c2RetMessage;
        tree->init(splitedCmd, c2Message);
        tree->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    // {
    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("tree");
    //     splitedCmd.push_back("C:\\Program Files");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     tree->init(splitedCmd, c2Message);
    //     tree->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }

    return true;
}
