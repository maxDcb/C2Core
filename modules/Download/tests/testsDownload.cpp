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

    return !res;
}


bool testDownload()
{
    std::unique_ptr<Download> download = std::make_unique<Download>();
    {
        std::string fileName = "test.txt";
        std::string outputFileName = "testDownload.txt";
        std::string fileContent = "tesDownload";

        std::ofstream outfile(fileName);
        outfile << fileContent;
        outfile.close();
        
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("download");
        splitedCmd.push_back(fileName);
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        download->init(splitedCmd, c2Message);
        download->process(c2Message, c2RetMessage);
        download->followUp(c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        std::ifstream myfile(outputFileName);
        if (myfile.is_open())
        {
            std::string buffer(std::istreambuf_iterator<char>(myfile), {});

            if (buffer!=fileContent)
            {
                return false;
            }
        }
        else 
        {
            return false;
        }
    }

    {
        std::string fileName = "test with space.txt";
        std::string outputFileName = "testDownload2.txt";
        std::string fileContent = "tesDownload2";

        std::ofstream outfile(fileName);
        outfile << fileContent;
        outfile.close();
        
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("download");
        splitedCmd.push_back("\"test");
        splitedCmd.push_back("with");
        splitedCmd.push_back("space.txt\"");
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        download->init(splitedCmd, c2Message);
        download->process(c2Message, c2RetMessage);
        download->followUp(c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        std::ifstream myfile(outputFileName);
        if (myfile.is_open())
        {
            std::string buffer(std::istreambuf_iterator<char>(myfile), {});

            if (buffer!=fileContent)
            {
                return false;
            }
        }
        else 
        {
            return false;
        }
    }

    {
        std::string fileName = "sdgsdfhkjjhgzetreyixwvccn.txt";
        std::string outputFileName = "notHere.txt";
        
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("download");
        splitedCmd.push_back(fileName);
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        download->init(splitedCmd, c2Message);
        download->process(c2Message, c2RetMessage);
        download->followUp(c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        if (c2RetMessage.errorCode()) 
        {
        } 
        else 
        {
            return false;
        }

        std::ifstream myfile;
		myfile.open(outputFileName, std::ios::binary);

		if(myfile)
		{
            return false;
        }
    }
}
