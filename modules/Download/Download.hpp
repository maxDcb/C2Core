#pragma once

#include "ModuleCmd.hpp"


class Download : public ModuleCmd
{

public:
    Download();
    ~Download();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int recurringExec(C2Message& c2RetMessage);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int followUp(const C2Message &c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
    std::string m_outputfile;
    std::ofstream m_output;
    std::ifstream m_input;
    std::streamsize m_fileSize;
    std::streamsize m_bytesRead;
};


#ifdef _WIN32

extern "C" __declspec(dllexport) Download * DownloadConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Download * DownloadConstructor();

#endif
