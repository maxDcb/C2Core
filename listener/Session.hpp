#pragma once

#include <iostream>
#include <chrono>
#include <queue>

#include "ModuleCmd.hpp"


class SessionListener
{
public:
		SessionListener(const std::string& listenerHash, const std::string& type, const std::string& host, int port)
		{
			m_listenerHash = listenerHash;
			m_type = type;
			m_host = host;
			m_port = port;
		}

		std::string getListenerHash()
		{
			return m_listenerHash;
		}

		std::string getType()
		{
			return m_type;
		}

		std::string getHost()
		{
			return m_host;
		}

		int getPort()
		{
			return m_port;
		}

private:
	std::string m_listenerHash;
	std::string m_type;
	std::string m_host;
	int m_port;
};


class Session
{
public:
	Session(const std::string& listenerHash, const std::string& beaconHash, const std::string& hostname, const std::string& username,
	const std::string& arch, const std::string& privilege, const std::string& os)
	{
		m_listenerHash=listenerHash;
		m_beaconHash=beaconHash;
		m_hostname=hostname;
		m_username=username;
		m_arch=arch;
		m_privilege=privilege;
		m_os=os;
		m_killed=false;

		m_lastProofOfLife = std::chrono::system_clock::now();
	}

	std::string getListenerHash()
	{
		return m_listenerHash;
	}

	std::string getBeaconHash()
	{
		return m_beaconHash;
	}

	std::string getUsername()
	{
		return m_username;
	}

	std::string getHostname()
	{
		return m_hostname;
	}

	std::string getArch()
	{
		return m_arch;
	}

	std::string getPrivilege()
	{
		return m_privilege;
	}

	std::string getOs()
	{
		return m_os;
	}

	void updatePoofOfLife()
	{
		m_lastProofOfLife = std::chrono::system_clock::now();
	}

	bool isSessionKilled()
	{
		return m_killed;
	}

	void setSessionAlive()
	{
		m_killed=false;
	}

	void setSessionKilled()
	{
		m_killed=true;
	}

	std::string getLastProofOfLife()
	{
		auto now = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsedSeconds = now-m_lastProofOfLife;

		std::string output = std::to_string(elapsedSeconds.count());
		if(m_killed)
			output="-1";

		return output;
	}

	int addTask(const C2Message& task)
	{
		m_messageToSend.push(task);	
		return m_messageToSend.size();
	}

	C2Message getTask()
	{
		C2Message output;
		if(!m_messageToSend.empty())
		{
			output.CopyFrom(m_messageToSend.front());
			m_messageToSend.pop();
		}
		return output;
	}

	int addTaskResult(const C2Message& taskResult)
	{
		m_messageToRead.push(taskResult);	
		return m_messageToRead.size();
	}

	C2Message getTaskResult()
	{
		C2Message output;
		if(!m_messageToRead.empty())
		{
			output.CopyFrom(m_messageToRead.front());
			m_messageToRead.pop();
		}
		return output;
	}

	bool addListener(const std::string& listenerHash, const std::string& type, const std::string& host, int port)
	{
		bool listenerAlreadyExist=false;
		for(int i=0; i<m_sessionListener.size(); i++)
		{
			if(m_sessionListener[i].getListenerHash()==listenerHash)
				listenerAlreadyExist=true;
		}

		if(listenerAlreadyExist==false)
		{
			SessionListener sessionListener(listenerHash, type, host, port);
			m_sessionListener.push_back(sessionListener);
			return true;
		}	

		return false;
	}

	bool rmListener(const std::string& listenerHash)
	{
		auto it = m_sessionListener.begin();
		while(it != m_sessionListener.end()) 
		{
			if((*it).getListenerHash() == listenerHash) 
			{
				it = m_sessionListener.erase(it);
				return true;
			} 
			else 
			{
				it++;
			}
		}
		return false;
	}

	const std::vector<SessionListener>& getListener()
	{
		return m_sessionListener;
	}


private:
	std::queue<C2Message> m_messageToRead;
    std::queue<C2Message> m_messageRead;

	std::queue<C2Message> m_messageToSend;
    std::queue<C2Message> m_messageSent;

	std::chrono::time_point<std::chrono::system_clock> m_lastProofOfLife;

	std::string m_listenerHash;
	std::string m_beaconHash;
	std::string m_hostname;
	std::string m_username;
	std::string m_arch;
	std::string m_privilege;
	std::string m_os;

	std::vector<SessionListener> m_sessionListener;

	bool m_killed;
};

