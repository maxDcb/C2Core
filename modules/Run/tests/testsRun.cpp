#include "../Run.hpp"

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

    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
        splitedCmd.push_back("whoami");

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
        splitedCmd.push_back("id");

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
        splitedCmd.push_back("dir");

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
#ifdef __linux__
        splitedCmd.push_back("/c ping 127.0.0.1 -c 1");
#elif _WIN32
        splitedCmd.push_back("/c ping 127.0.0.1 /n 1");
#endif

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
        splitedCmd.push_back("calc.exe");

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("run");
        splitedCmd.push_back(".\\test.bat");

        C2Message c2Message;
        C2Message c2RetMessage;
        run->init(splitedCmd, c2Message);
        run->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    return true;
}
