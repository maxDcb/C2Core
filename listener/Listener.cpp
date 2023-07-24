#include "Listener.hpp"


#ifdef __linux__

#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/shared_ptr.hpp>

bool port_in_use(unsigned short port) 
{
    using namespace boost::asio;
    using ip::tcp;

    io_service svc;
    tcp::acceptor a(svc);

    boost::system::error_code ec;
    a.open(tcp::v4(), ec) || a.bind({ tcp::v4(), port }, ec);

    return ec == error::address_in_use;
}

#elif _WIN32
#endif


using namespace std;


Listener::Listener(const std::string& host, int port, const std::string& type)
{
#ifdef __linux__

	bool isPortInUse = port_in_use(port);
	if(isPortInUse)
		throw std::runtime_error("Port Already Used.");
		
#elif _WIN32
#endif

	m_host=host;
	m_port = port;
	m_type = type;
	m_listenerHash = random_string(SizeListenerHash);
}


const std::string & Listener::getHost()
{
	return m_host;
}


int Listener::getPort()
{
	return m_port;
}


const std::string & Listener::getType()
{
	return m_type;
}


const std::string & Listener::getListenerHash()
{
	return m_listenerHash;
}


int Listener::getNumberOfSession()
{
	return m_sessions.size();
}


std::shared_ptr<Session> Listener::getSessionPtr(int idxSession)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	if(idxSession<m_sessions.size())
	{
		std::shared_ptr<Session> ptr = m_sessions[idxSession];
		return ptr;
	}
	else 
		return nullptr;
}


std::shared_ptr<Session> Listener::getSessionPtr(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);


	for(int idxSession=0; idxSession<m_sessions.size(); idxSession++)
	{
		if (beaconHash == m_sessions[idxSession]->getBeaconHash())
		{
			std::shared_ptr<Session> ptr = m_sessions[idxSession];
			return ptr;
		}
	}
	return nullptr;
}


bool Listener::isSessionExist(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
		}
	}
	return sessionExist;
}


bool Listener::updateSessionPoofOfLife(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->updatePoofOfLife();
			(*it)->setSessionAlive();
		}
	}
	return sessionExist;
}


bool Listener::addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& host, int port)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->addListener(listenerHash, type, host, port);
		}
	}
	return sessionExist;
}



bool Listener::rmSessionListener(const std::string& beaconHash, const std::string& listenerHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->rmListener(listenerHash);
		}
	}
	return sessionExist;
}



std::vector<SessionListener> Listener::getSessionListenerInfos()
{
	std::vector<SessionListener> sessionListenerList;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		sessionListenerList.insert(sessionListenerList.end(), (*it)->getListener().begin(), (*it)->getListener().end());
	}
	return sessionListenerList;
}


bool Listener::markSessionKilled(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->setSessionKilled();
		}
	}
	return sessionExist;
}


void Listener::queueTask(const std::string& beaconHash, const C2Message& c2Message)
{
	addTask(c2Message, beaconHash);
}


bool Listener::addTask(const C2Message& task, const std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->addTask(task);
		}
	}
	return sessionExist;
}


C2Message Listener::getTask(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	C2Message output;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			output = (*it)->getTask();
		}
	}

	return output;
}


bool Listener::addTaskResult(const C2Message& taskResult, std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->addTaskResult(taskResult);
		}
	}
	return sessionExist;
}


C2Message Listener::getTaskResult(std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	C2Message output;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			output = (*it)->getTaskResult();
		}
	}

	return output;
}


// Main function of the listener
// input is the message send by the beacon to the listener
// output is the message send by listener to the beacon
bool Listener::handleMessages(const std::string& input, std::string& output)
{
	std::string key="dfsdgferhzdzxczevre5595485sdg";
	std::string data = base64_decode(input);
	XOR(data, key);

	// Mutli Session, Multi message 
	MultiBundleC2Message multiBundleC2Message;
	multiBundleC2Message.ParseFromArray(data.data(), (int)data.size());

	bool isTaskToSend=false;
	MultiBundleC2Message multiBundleC2MessageRet;
	for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
	{
		// For each session (direct session and childs)
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

		std::string beaconHash = bundleC2Message->beaconhash();
		if(beaconHash.size()==SizeBeaconHash)
		{
			bool SessionExis = isSessionExist(beaconHash);
			if(SessionExis==false)
			{
				// Create session with the pair beaconHash / listenerHash
				// If listenerHash is already fill that mean the session is from an other listener originaly
				// Else it's a "simple" session
				std::string listenerhash = bundleC2Message->listenerhash();
				if(listenerhash.empty())
					listenerhash = getListenerHash();

				std::string username = bundleC2Message->username();
				std::string hostname = bundleC2Message->hostname();
				std::string arch = bundleC2Message->arch();
				std::string privilege = bundleC2Message->privilege();
				std::string os = bundleC2Message->os();

				std::shared_ptr<Session> session = make_shared<Session>(listenerhash, beaconHash, hostname, username, arch, privilege, os);
				m_sessions.push_back(std::move(session));
			}
			else
			{
				updateSessionPoofOfLife(beaconHash);
			}

			// For each message in this session
			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);

				if(!c2Message.returnvalue().empty())
				{
					addTaskResult(c2Message, beaconHash);
				}

				if(c2Message.instruction()==EndCmd)
				{
					markSessionKilled(beaconHash);
				}	
				else if(c2Message.instruction()==ListenerCmd)
				{
					std::string cmd = c2Message.cmd();
					std::vector<std::string> splitedCmd;
					std::string delimiter = " ";
					splitList(cmd, delimiter, splitedCmd);

					if(splitedCmd[0]==StartCmd && splitedCmd[1]=="smb")
					{
						int localPort = 0;
						
						std::string type=ListenerSmbType;
						std::string host="127.0.0.1";

						std::shared_ptr<Session> ptr = getSessionPtr(beaconHash);
						if(ptr)
							host = ptr->getHostname();

						addSessionListener(beaconHash, c2Message.returnvalue(), type, host, localPort);
					}
					if(splitedCmd[0]==StartCmd && splitedCmd[1]=="tcp")
					{
						// TODO
						int localPort = std::stoi(splitedCmd[3]);
						
						std::string type=ListenerTcpType;
						std::string host="127.0.0.1";

						std::shared_ptr<Session> ptr = getSessionPtr(beaconHash);
						if(ptr)
							host = ptr->getHostname();

						addSessionListener(beaconHash, c2Message.returnvalue(), type, host, localPort);
					}
					else if(splitedCmd[0]==StopCmd)
					{
						rmSessionListener(beaconHash, c2Message.returnvalue());
					}
				}	
			}

			// Look for tasks in the queu for the this beacon
			C2Message c2Message = getTask(beaconHash);
			if(!c2Message.instruction().empty())
			{
				isTaskToSend=true;
				BundleC2Message *bundleC2Message = multiBundleC2MessageRet.add_bundlec2messages();
				bundleC2Message->set_beaconhash(beaconHash);

				while(!c2Message.instruction().empty())
				{
					C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
					addedC2MessageRet->CopyFrom(c2Message);
					c2Message = getTask(beaconHash);	
				}	
			}
		}
	}

	data="";
	if(isTaskToSend)
		multiBundleC2MessageRet.SerializeToString(&data);

	XOR(data, key);
	output = base64_encode(data);

	return isTaskToSend;
}