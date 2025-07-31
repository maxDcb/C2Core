#include "../KillProcess.hpp"
#include "../../ModuleCmd/Tools.hpp"
#include <chrono>
#include <thread>
#ifdef __linux__
#include <signal.h>
#include <sys/wait.h>
#elif _WIN32
#include <windows.h>
#endif

bool testKillProcess();

int main()
{
    bool res;
    std::cout << "[+] testKillProcess" << std::endl;
    res = testKillProcess();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testKillProcess()
{
    bool ok = true;

    int pid;
#ifdef __linux__
    pid = launchProcess("sleep 30");
    std::this_thread::sleep_for(std::chrono::seconds(1));
#elif _WIN32
    pid = launchProcess("C:\\Windows\\System32\\notepad.exe");
    Sleep(1000);
#endif

    KillProcess kp;
    std::vector<std::string> cmd = {"killProcess", std::to_string(pid)};
    C2Message msg, ret;
    kp.init(cmd, msg);
    msg.set_pid(pid);
    kp.process(msg, ret);

#ifdef __linux__
    ok &= ret.errorCode() == -1;
#elif _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h)
    {
        DWORD code = 0;
        bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
        CloseHandle(h);
        ok &= !alive;
    }
    else
    {
        ok &= true;
    }
#endif
    return ok;
}
