#include "KillProcess.hpp"

#include "Common.hpp"

#include <cstring>
#include <charconv>
#ifdef __linux__
#include <signal.h>
#include <unistd.h>
#elif _WIN32
#include <windows.h>
#endif

using namespace std;

constexpr std::string_view moduleName = "killProcess";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) KillProcess* KillProcessConstructor()
{
    return new KillProcess();
}
#else
__attribute__((visibility("default"))) KillProcess* KillProcessConstructor()
{
    return new KillProcess();
}
#endif

KillProcess::KillProcess()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

KillProcess::~KillProcess()
{
}

std::string KillProcess::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "killProcess Module:\n";
    info += "Terminate a process by PID.\n";
    info += "\nUsage:\n";
    info += " - killProcess <pid>\n";
#endif
    return info;
}

int KillProcess::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (splitedCmd.size() == 2 && splitedCmd[0] == moduleName)
    {
        int pid = 0;
        const std::string& value = splitedCmd[1];
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), pid);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || pid <= 0)
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_pid(pid);
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}

#define ERROR_KILL_PROCESS 1
int KillProcess::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    int pid = c2Message.pid();
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_pid(pid);
    c2RetMessage.set_returnvalue({});
    if (pid <= 0)
    {
        c2RetMessage.set_errorCode(ERROR_KILL_PROCESS);
        return 0;
    }
#ifdef __linux__
    if (kill(pid, SIGKILL) == 0)
    {
        c2RetMessage.set_errorCode(0);
        c2RetMessage.set_returnvalue("Killed.");
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_KILL_PROCESS);
    }
#elif _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess)
    {
        BOOL ok = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        if (ok)
        {
            c2RetMessage.set_errorCode(0);
            c2RetMessage.set_returnvalue("Killed.");
        }
        else
            c2RetMessage.set_errorCode(ERROR_KILL_PROCESS);
    }
    else
    {
        c2RetMessage.set_errorCode(ERROR_KILL_PROCESS);
    }
#endif
    return 0;
}

int KillProcess::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    errorMsg.clear();
    if (c2RetMessage.errorCode() == ERROR_KILL_PROCESS)
        errorMsg = "Failed: Could not kill process";
#endif
    return 0;
}
