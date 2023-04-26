#include "../Download.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testDownload();

int main()
{
    bool res;

    std::cout << "[+] testDownload" << std::endl;
    res = testDownload();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testDownload()
{
    std::ofstream outfile("test2.txt");
    outfile << "testDownload" << std::endl;
    outfile.close();

    std::unique_ptr<Download> download = std::make_unique<Download>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("download");
        splitedCmd.push_back("test2.txt");
        splitedCmd.push_back("testDownload.txt");

        C2Message c2Message;
        C2Message c2RetMessage;
        download->init(splitedCmd, c2Message);
        download->process(c2Message, c2RetMessage);
        download->followUp(c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    std::ifstream myfile("testDownload.txt");
    if (myfile.is_open())
        return true;
    else
        return false;   
}
