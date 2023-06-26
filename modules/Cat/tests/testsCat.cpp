#include "../Cat.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testCat();

int main()
{
    bool res;

    std::cout << "[+] testCat" << std::endl;
    res = testCat();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}

bool testCat()
{
    std::ofstream outfile("test1.txt");
    outfile << "testCat" << std::endl;
    outfile.close();

    std::unique_ptr<Cat> cat = std::make_unique<Cat>();
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cat");
        splitedCmd.push_back("test1.txt");

        C2Message c2Message;
        C2Message c2RetMessage;
        cat->init(splitedCmd, c2Message);
        cat->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }


    return true;
}
