#pragma once

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    #include <algorithm>
    #include <cctype>
#endif
#include <iostream>
#include <fstream>
#include <memory>
#include <chrono>
#include <random>
#include <vector>
#include <thread>

#include <C2Message.hpp>

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
struct ModulePreparedShellcodeTask
{
    std::string inputFile;
    std::string payload;
    std::string executionMode;
    std::string displayCommand;
    int pid = -1;
};
#endif


enum OSCompatibility {
    OS_NONE    = 0,
    OS_LINUX   = 1 << 0,  // 0001
    OS_MAC     = 1 << 1,  // 0010
    OS_WINDOWS = 1 << 2,  // 0100
    OS_ALL     = OS_LINUX | OS_MAC | OS_WINDOWS
};


//
// ModuleCmd
//
class ModuleCmd
{
    
public:
    ModuleCmd(const std::string& name, unsigned long long hash=0)
    {
        m_name=name;
        m_hash=hash;
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
        m_windowsArch="x64";
#endif
    }

    ~ModuleCmd()
    {

    }

    std::string getName()
    {
        return m_name;
    }

    unsigned long long getHash()
    {
        return m_hash;
    }

    int setDirectories( const std::string& teamServerModulesDirectoryPath,
                        const std::string& linuxModulesDirectoryPath,
                        const std::string& windowsModulesDirectoryPath,
                        const std::string& linuxBeaconsDirectoryPath,
                        const std::string& windowsBeaconsDirectoryPath,
                        const std::string& toolsDirectoryPath,
                        const std::string& scriptsDirectoryPath)
    {
        m_teamServerModulesDirectoryPath=teamServerModulesDirectoryPath;
        m_linuxModulesDirectoryPath=linuxModulesDirectoryPath;
        m_windowsModulesDirectoryPath=windowsModulesDirectoryPath;
        m_linuxBeaconsDirectoryPath=linuxBeaconsDirectoryPath;
        m_windowsBeaconsDirectoryPath=windowsBeaconsDirectoryPath;
        m_toolsDirectoryPath=toolsDirectoryPath;
        m_scriptsDirectoryPath=scriptsDirectoryPath;

        return 0;
    };

    virtual std::string getInfo() = 0;

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    virtual int setWindowsArch(const std::string& windowsArch)
    {
        std::string normalizedArch = windowsArch;
        std::transform(normalizedArch.begin(), normalizedArch.end(), normalizedArch.begin(), [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });

        if(normalizedArch=="amd64" || normalizedArch=="x86_64")
            normalizedArch="x64";
        else if(normalizedArch=="i386" || normalizedArch=="i686")
            normalizedArch="x86";
        else if(normalizedArch=="aarch64")
            normalizedArch="arm64";

        if(normalizedArch=="x64" || normalizedArch=="x86" || normalizedArch=="arm64")
            m_windowsArch=normalizedArch;
        else
            m_windowsArch="x64";

        return 0;
    }
#endif

    // if an error ocurre:
    // set_returnvalue(errorMsg) && return -1
    virtual int init(std::vector<std::string>& splitedCmd, C2Message& c2Message) = 0;
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    virtual int initPreparedShellcode(const ModulePreparedShellcodeTask& task, C2Message& c2Message)
    {
        (void)task;
        c2Message.set_returnvalue("Prepared shellcode tasks are not supported by this module.");
        return -1;
    };
#endif
    virtual int initConfig(const nlohmann::json &config) {return 0;};
    virtual int process(C2Message& c2Message, C2Message& c2RetMessage) = 0;
    virtual int followUp(const C2Message &c2RetMessage) {return 0;};
    virtual int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg) {return 0;};
    virtual int recurringExec (C2Message& c2RetMessage) {return 0;};
    virtual int osCompatibility () {return OS_NONE;};

protected:
    std::string m_name;
    unsigned long long m_hash;

    std::string m_teamServerModulesDirectoryPath;
    std::string m_linuxModulesDirectoryPath;
    std::string m_windowsModulesDirectoryPath;
    std::string m_linuxBeaconsDirectoryPath;
    std::string m_windowsBeaconsDirectoryPath;
    std::string m_toolsDirectoryPath;
    std::string m_scriptsDirectoryPath;
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    std::string m_windowsArch;
#endif

private:
    
};
