#include "../AssemblyExec.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testAssemblyExec();

int main()
{
    bool res;
    
    std::cout << "[+] testAssemblyExec" << std::endl;
    res = testAssemblyExec();
    if (res)
     std::cout << "[+] Sucess" << std::endl;
    else
     std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testAssemblyExec()
{
    std::unique_ptr<AssemblyExec> assemblyExec = std::make_unique<AssemblyExec>();

    {
#ifdef __linux__

#elif _WIN32
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\Rubeus.exe");
        splitedCmd.push_back("triage");

        C2Message c2Message;
        C2Message c2RetMessage;
        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
#endif

    }
    {
#ifdef __linux__

#elif _WIN32
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\mimikatz.exe");
        splitedCmd.push_back("\"sleep 10000\""); 
        splitedCmd.push_back("\"exit\"");


        C2Message c2Message;
        C2Message c2RetMessage;
        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
#endif

    }
//     {
// #ifdef __linux__

// #elif _WIN32
//         std::vector<std::string> splitedCmd;
//         splitedCmd.push_back("assemblyExec");
//         splitedCmd.push_back("-e");
//         splitedCmd.push_back(".\\mimikatz.exe");
//         splitedCmd.push_back("\"sleep 1000000\""); 
//         splitedCmd.push_back("\"exit\"");


//         C2Message c2Message;
//         C2Message c2RetMessage;
//         assemblyExec->init(splitedCmd, c2Message);
//         assemblyExec->process(c2Message, c2RetMessage);

//         std::string output = "\n\noutput:\n";
//         output += c2RetMessage.returnvalue();
//         output += "\n";
//         std::cout << output << std::endl;
// #endif

//     }

    return true;
}
