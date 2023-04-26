#include "../Upload.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testUpload();

int main()
{
    bool res;

    std::cout << "[+] testUpload" << std::endl;
    res = testUpload();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testUpload()
{
    std::ofstream outfile("test1.txt");
    outfile << "testUpload" << std::endl;
    outfile.close();

    std::unique_ptr<Upload> upload = std::make_unique<Upload>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("upload");
        splitedCmd.push_back("test1.txt");
        splitedCmd.push_back("testUpload.txt");

        C2Message c2Message;
        C2Message c2RetMessage;
        upload->init(splitedCmd, c2Message);
        upload->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }

    std::ifstream myfile("testUpload.txt");
    if (myfile.is_open())
        return true;
    else
        return false;
}
