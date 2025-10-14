#include "ModuleTemplate.hpp"

#include "Common.hpp"

#include <cstring>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "moduleTemplate";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) ModuleTemplate* ModuleTemplateConstructor() 
{
    return new ModuleTemplate();
}

#else

__attribute__((visibility("default"))) ModuleTemplate* ModuleTemplateConstructor() 
{
    return new ModuleTemplate();
}

#endif


ModuleTemplate::ModuleTemplate()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}


ModuleTemplate::~ModuleTemplate()
{
}


std::string ModuleTemplate::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "moduleTemplate:\n";
    info += "ModuleTemplate for easy developement of new modules\n";
    info += "This is the help that will be display when you do 'ModuleTemplate help' or when their is an error during the init methode\n";
    info += "exemple:\n";
    info += "- moduleTemplate args\n";
#endif
    return info;
}


// Method that will be trigged server side to construct the message that will be send to the beacon and interpreted by the process method
int ModuleTemplate::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
    if (splitedCmd.size() >= 2 )
    {
        string args = "args from the splited command line";
        args = splitedCmd[1];

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_data(args);
    }
    else
    {
        // error message deiplay if something is wrong
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}


// Method that will be trigged server side after the retrun message is received
// For exemple a file to write on the disk
int ModuleTemplate::followUp(const C2Message &c2RetMessage)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
    // check if there is an error
    if(c2RetMessage.errorCode()==-1)
    {
        std::string args = c2RetMessage.args();
    }
#endif
    return 0;
}


#define ERROR_CODE_1 1 


// Method that will be trigged beacon side, the main processing method
int ModuleTemplate::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2RetMessage.instruction());

    std::string data = c2Message.data();
    if( data == "arg1" ) 
    {
        std::string buffer = "return value that will be shown in the client";
        c2RetMessage.set_returnvalue(buffer);
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_CODE_1);
    }

    return 0;
}


// Method that will be trigged server side after the retrun message is received, in case of error
int ModuleTemplate::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_CODE_1)
            errorMsg = "Failed: An error occured and that is the error message that will be display to the user";
    }
#endif
    return 0;
}
