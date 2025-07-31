#include "../Powershell.hpp"

#include <fstream>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testPowershell();

int main()
{
    bool res;

    std::cout << "[+] testPowershell" << std::endl;
    res = testPowershell();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


bool testPowershell()
{
#ifdef __linux__
    // Module is Windows only; on Linux just ensure it can be instantiated.
    std::unique_ptr<Powershell> powershell = std::make_unique<Powershell>();
    (void)powershell;
    return true;
#else
    std::unique_ptr<Powershell> powershell = std::make_unique<Powershell>();

    {
        std::string testString = "test";

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("powershellt");
        splitedCmd.push_back("echo");
        splitedCmd.push_back(testString);
        splitedCmd.push_back("|");
        splitedCmd.push_back("write-output");

        C2Message c2Message;
        C2Message c2RetMessage;
        powershell->init(splitedCmd, c2Message);
        powershell->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        if (c2RetMessage.returnvalue().compare(0, testString.length(), testString) == 0) 
        {
        } 
        else 
        {
            return false;
        }
    }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("powershellt");
        splitedCmd.push_back("whoami /priv");
        splitedCmd.push_back("|");
        splitedCmd.push_back("write-output");

        C2Message c2Message;
        C2Message c2RetMessage;
        powershell->init(splitedCmd, c2Message);
        powershell->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
    {
        std::string scriptFile = "HelloWorlModule.ps1";

        std::string script = R"(
# Define the PrintHelloWorld function
function PrintHelloWorld {
    Write-Output "Hello, World!"
}

# Export the function to make it available to other scripts
Export-ModuleMember -Function PrintHelloWorld
)";
        std::ofstream outFile(scriptFile);
        if (!outFile) 
        {
            return false;
        }
        outFile << script;
        outFile.close();
            
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("powershellt");
        splitedCmd.push_back("-i");
        splitedCmd.push_back(scriptFile);

        C2Message c2Message;
        C2Message c2RetMessage;
        powershell->init(splitedCmd, c2Message);
        powershell->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;

        std::vector<std::string> splitedCmd1;
        splitedCmd1.push_back("powershellt");
        splitedCmd1.push_back("PrintHelloWorld");

        C2Message c2Message1;
        C2Message c2RetMessage1;
        powershell->init(splitedCmd1, c2Message1);
        powershell->process(c2Message1, c2RetMessage1);

        std::string output1 = "\n\noutput:\n";
        output1 += c2RetMessage1.returnvalue();
        output1 += "\n";
        std::cout << output1 << std::endl;

        std::string toFind = "Hello, World!";
        if (output1.find(toFind) != std::string::npos) 
        {
        } 
        else 
        {
            return false;
        }
    }

    return true;
#endif
}