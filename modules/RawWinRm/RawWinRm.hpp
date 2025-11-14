#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class RawWinRm : public ModuleCmd
{
public:
    RawWinRm();
    ~RawWinRm();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);
    int followUp(const C2Message& c2RetMessage);

    int osCompatibility()
    {
        return OS_WINDOWS;
    }

private:
#ifdef _WIN32
    int runCommand(const C2Message& c2Message, std::string& result) const;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) RawWinRm* RawWinRmConstructor();
#else
extern "C" __attribute__((visibility("default"))) RawWinRm* RawWinRmConstructor();
#endif
