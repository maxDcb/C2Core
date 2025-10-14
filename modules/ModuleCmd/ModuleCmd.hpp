#pragma once

#include <iostream>
#include <fstream>
#include <memory>
#include <chrono>
#include <random>
#include <vector>
#include <thread>

#include <C2Message.hpp>


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

    // if an error ocurre:
    // set_returnvalue(errorMsg) && return -1
    virtual int init(std::vector<std::string>& splitedCmd, C2Message& c2Message) = 0;
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

private:
    
};
