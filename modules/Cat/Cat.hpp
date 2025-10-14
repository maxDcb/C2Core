#pragma once

#include "ModuleCmd.hpp"


class Cat : public ModuleCmd
{

public:
    Cat();
    ~Cat();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
    int osCompatibility() 
    {
        return OS_LINUX | OS_WINDOWS;
    }


private:

};


#ifdef _WIN32

extern "C" __declspec(dllexport) Cat * CatConstructor();

#else

extern "C"  __attribute__((visibility("default"))) Cat * CatConstructor();

#endif
