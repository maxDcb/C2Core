#pragma once

#include <iostream>
#include <chrono>
#include <queue>
#include <mutex>

#include "CommonCommand.hpp"
#include "Session.hpp"
#include "Common.hpp"


// TODO set an enum
const std::string ListenerHttpType = "http";
const std::string ListenerHttpsType = "https";
const std::string ListenerTcpType = "tcp";
const std::string ListenerSmbType = "smb";
const std::string ListenerGithubType = "github";


class Listener
{

public:
	Listener(const std::string& host, int port, const std::string& type);
	virtual ~Listener(){};

	const std::string & getHost();
	int getPort();
	const std::string & getType();
	const std::string & getListenerHash();
	int getNumberOfSession();

	// Session
	std::shared_ptr<Session> getSessionPtr(int idxSession);
	std::shared_ptr<Session> getSessionPtr(std::string& beaconHash, std::string& listenerHash);
	bool isSessionExist(std::string& beaconHash, std::string& listenerHash);
	bool updateSessionPoofOfLife(std::string& beaconHash, std::string& lastProofOfLife);
	bool markSessionKilled(std::string& beaconhash);

	// Session Listener
	bool addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& host, int port);
	bool rmSessionListener(const std::string& beaconHash, const std::string& listenerHash);
	std::vector<SessionListener> getSessionListenerInfos();

	// Task & Task Result
	void queueTask(const std::string& beaconHash, const C2Message& c2Message);
	bool addTask(const C2Message& task, const std::string& beaconHash);
	C2Message getTask(std::string& beaconHash);
	bool addTaskResult(const C2Message& taskResult, std::string& beaconHash);
	C2Message getTaskResult(std::string& beaconHash);

protected:
	bool execInstruction(std::vector<std::string>& splitedCmd, C2Message& c2Message);
	bool handleMessages(const std::string& input, std::string& output);

	std::string m_hostname;

	int m_port;
	std::string m_host;
	std::string m_type;
	std::string m_listenerHash;

	std::vector<std::shared_ptr<Session>> m_sessions;

private:
	std::mutex m_mutex;
	
};
