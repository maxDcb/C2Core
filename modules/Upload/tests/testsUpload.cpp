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

    return !res;
}

bool testUpload()
{
    std::unique_ptr<Upload> upload = std::make_unique<Upload>();
    {
        std::string fileName = "testUpload.txt";
        std::string outputFileName = "testUpload_.txt";
        std::string fileContent = "testUpload";

        std::ofstream outfile(fileName);
        outfile << fileContent;
        outfile.close();

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("upload");
        splitedCmd.push_back(fileName);
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        upload->init(splitedCmd, c2Message);
        upload->process(c2Message, c2RetMessage);

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
        std::string fileName = "test Upload 2.txt";
        std::string outputFileName = "test Upload 2_.txt";
        std::string fileContent = "testUpload2";

        std::ofstream outfile(fileName);
        outfile << fileContent;
        outfile.close();

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("");
        splitedCmd.push_back("\"test"); splitedCmd.push_back("Upload"); splitedCmd.push_back("2.txt\"");
        splitedCmd.push_back("\"test"); splitedCmd.push_back("Upload"); splitedCmd.push_back("2_.txt\"");

        C2Message c2Message;
        C2Message c2RetMessage;
        upload->init(splitedCmd, c2Message);
        upload->process(c2Message, c2RetMessage);

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
        splitedCmd.push_back("upload");
        splitedCmd.push_back(fileName);
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        upload->init(splitedCmd, c2Message);
        upload->process(c2Message, c2RetMessage);

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
