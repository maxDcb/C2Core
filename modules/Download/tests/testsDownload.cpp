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


bool areFilesIdentical(const std::string& file1, const std::string& file2) {
    std::ifstream f1(file1, std::ios::binary | std::ios::ate);
    std::ifstream f2(file2, std::ios::binary | std::ios::ate);

    if (!f1 || !f2) {
        std::cerr << "Failed to open one or both files." << std::endl;
        return false;
    }

    if (f1.tellg() != f2.tellg()) {
        return false; // Different sizes
    }

    f1.seekg(0, std::ios::beg);
    f2.seekg(0, std::ios::beg);

    std::vector<char> buffer1((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
    std::vector<char> buffer2((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());

    return buffer1 == buffer2;
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

        std::string errorMsg;
        download->errorCodeToMsg(c2RetMessage, errorMsg);

        std::string error = "errorMsg:\n";
        error += errorMsg;
        error += "\n";
        std::cout << error << std::endl;

        std::string output = "output:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        if (areFilesIdentical(fileName, outputFileName)) 
        {
        } 
        else 
        {
            std::cout << "The files are different." << std::endl;
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

        std::string errorMsg;
        download->errorCodeToMsg(c2RetMessage, errorMsg);

        std::string error = "errorMsg:\n";
        error += errorMsg;
        error += "\n";
        std::cout << error << std::endl;

        std::string output = "output:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        if (areFilesIdentical(fileName, outputFileName)) 
        {
        } 
        else 
        {
            std::cout << "The files are different." << std::endl;
            return false;
        }
    }

    {
        std::string fileName = "rockyou.txt.gz";
        std::string outputFileName = "rockyouCopy.txt.gz";

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("download");
        splitedCmd.push_back(fileName);
        splitedCmd.push_back(outputFileName);

        C2Message c2Message;
        C2Message c2RetMessage;
        download->init(splitedCmd, c2Message);
        download->process(c2Message, c2RetMessage);
        download->followUp(c2RetMessage);

        std::string errorMsg;
        download->errorCodeToMsg(c2RetMessage, errorMsg);

        std::string error = "errorMsg:\n";
        error += errorMsg;
        error += "\n";
        std::cout << error << std::endl;

        std::string output = "output:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        while(true)
        {
            C2Message c2RetMessageNew;
            download->recurringExec(c2RetMessageNew);
            download->followUp(c2RetMessageNew);
            
            std::string errorMsg;
            download->errorCodeToMsg(c2RetMessageNew, errorMsg);

            std::string error = "errorMsg:\n";
            error += errorMsg;
            error += "\n";
            std::cout << error << std::endl;

            std::string output = "output:\n";
            output += c2RetMessageNew.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if("Success" == c2RetMessageNew.returnvalue())
                break;
        }

        if (areFilesIdentical(fileName, outputFileName)) 
        {
        } 
        else 
        {
            std::cout << "The files are different." << std::endl;
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

        std::string errorMsg;
        download->errorCodeToMsg(c2RetMessage, errorMsg);

        std::string error = "errorMsg:\n";
        error += errorMsg;
        error += "\n";
        std::cout << error << std::endl;

        std::string output = "output:\n";
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

    return true;
}
