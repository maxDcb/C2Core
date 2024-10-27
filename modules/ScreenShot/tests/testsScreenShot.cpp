#include "../ScreenShot.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testScreenShot();

int main()
{
    bool res;

    std::cout << "[+] testScreenShot" << std::endl;
    res = testScreenShot();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testScreenShot()
{
    std::ofstream outfile("test1.txt");
    outfile << "testScreenShot" << std::endl;
    outfile.close();

    std::unique_ptr<ScreenShot> screenShot = std::make_unique<ScreenShot>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("screenShot");

        C2Message c2Message;
        C2Message c2RetMessage;
        screenShot->init(splitedCmd, c2Message);
        screenShot->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }


    return true;
}
