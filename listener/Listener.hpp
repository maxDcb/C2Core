#pragma once

#include <iostream>
#include <chrono>
#include <queue>
#include <mutex>

#include "CommonCommand.hpp"
#include "Session.hpp"
#include "Common.hpp"

#ifdef BUILD_TEAMSERVER
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"
#endif

class Listener
{

public:
	Listener(const std::string& param1, const std::string& param2, const std::string& type);
	virtual ~Listener(){};

	const std::string & getParam1();
	const std::string & getParam2();
	const std::string & getType();
	const std::string & getListenerHash();
	int getNumberOfSession();

	// Session
	std::shared_ptr<Session> getSessionPtr(int idxSession);
	std::shared_ptr<Session> getSessionPtr(std::string& beaconHash, std::string& listenerHash);
	bool isSessionExist(const std::string& beaconHash, const std::string& listenerHash);
	bool updateSessionPoofOfLife(std::string& beaconHash, std::string& lastProofOfLife);
	bool markSessionKilled(std::string& beaconhash);

	// Session Listener
	bool addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& param1, const std::string& param2);
	bool rmSessionListener(const std::string& beaconHash, const std::string& listenerHash);
	std::vector<SessionListener> getSessionListenerInfos();

	// Task & Task Result
	void queueTask(const std::string& beaconHash, const C2Message& c2Message);
	bool addTask(const C2Message& task, const std::string& beaconHash);
	C2Message getTask(std::string& beaconHash);
	bool addTaskResult(const C2Message& taskResult, std::string& beaconHash);
	C2Message getTaskResult(const std::string& beaconHash);

	// SocksSession
	bool isSocksSessionExist(std::string& beaconHash, std::string& listenerHash);
	bool addSocksTaskResult(const C2Message& taskResult, std::string& beaconHash);
	C2Message getSocksTaskResult(const std::string& beaconHash);

	// set the listener as primary (meaning launch from the teamserver)
	void setIsPrimary()
	{
		m_isPrimary=true;
	}

protected:
	bool execInstruction(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	bool handleMessages(const std::string& input, std::string& output);

	std::string m_key;
	std::string m_param1;
	std::string m_param2;
	std::string m_type;
	bool m_isPrimary;

	std::string m_listenerHash;
	std::string m_hostname;

	std::vector<std::shared_ptr<Session>> m_sessions;
	std::vector<std::shared_ptr<SocksSession>> m_socksSessions;

#ifdef BUILD_TEAMSERVER
	std::shared_ptr<spdlog::logger> m_logger;
#endif

private:
	std::mutex m_mutex;	
};
