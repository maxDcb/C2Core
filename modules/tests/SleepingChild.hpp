#pragma once

#include <chrono>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace test_helpers
{
inline bool isSleepingChild(int argc, char** argv)
{
    if (argc != 2 || std::string(argv[1]) != "--sleeping-child")
        return false;
    std::this_thread::sleep_for(std::chrono::seconds(30));
    return true;
}

struct SleepingChild
{
    int pid = -1;
#ifdef _WIN32
    HANDLE process = nullptr;
    HANDLE thread = nullptr;
#endif

    explicit SleepingChild(const char* executable)
    {
#ifdef _WIN32
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        std::string command = "\"" + std::string(executable) + "\" --sleeping-child";
        if (CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info))
        {
            pid = static_cast<int>(info.dwProcessId);
            process = info.hProcess;
            thread = info.hThread;
        }
#else
        (void)executable;
        const pid_t child = fork();
        if (child == 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            _exit(0);
        }
        pid = static_cast<int>(child);
#endif
    }

    SleepingChild(const SleepingChild&) = delete;
    SleepingChild& operator=(const SleepingChild&) = delete;

    bool waitForTermination()
    {
        if (pid <= 0)
            return false;
#ifdef _WIN32
        return WaitForSingleObject(process, 5000) == WAIT_OBJECT_0;
#else
        int status = 0;
        const pid_t waited = waitpid(static_cast<pid_t>(pid), &status, 0);
        if (waited == pid)
            pid = -1;
        return waited > 0 && WIFSIGNALED(status);
#endif
    }

    ~SleepingChild()
    {
#ifdef _WIN32
        if (process)
        {
            if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT)
                TerminateProcess(process, 1);
            WaitForSingleObject(process, 5000);
            CloseHandle(process);
        }
        if (thread)
            CloseHandle(thread);
#else
        if (pid > 0)
        {
            kill(static_cast<pid_t>(pid), SIGKILL);
            int status = 0;
            waitpid(static_cast<pid_t>(pid), &status, 0);
        }
#endif
    }
};
}
