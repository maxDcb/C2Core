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

        m_stopThread.store(false);
        m_smbServ = std::make_unique<std::thread>(&ListenerSmb::launchSmbServ, this);
}


ListenerSmb::~ListenerSmb()
{
    m_stopThread.store(true);
    wakeServer();

    if(m_smbServ && m_smbServ->joinable())
        m_smbServ->join();

        delete m_serverSmb;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("SMB listener stopped on {} pipe {}", m_param1, m_param2);
#endif
}

void ListenerSmb::wakeServer()
{
    try
    {
        PipeHandler::Client client(".", m_param2);
        if(client.initConnection())
        {
            std::string stopMessage = "__stop__";
            client.sendData(stopMessage);
            client.closeConnection();
        }
    }
    catch (...)
    {
    }
}


void ListenerSmb::launchSmbServ()
{
    try 
    {
        while(!m_stopThread.load())
        {
                        if(!m_serverSmb->initServer())
                        {
                                if(!m_stopThread.load())
                                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                        }

                        bool res = false;
                        string input;
                        do
                        {
                                res = m_serverSmb->receiveData(input);
                                if(input.empty() && !m_stopThread.load())
                                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        }
                        while(!m_stopThread.load() && input.empty());

                        if(m_stopThread.load())
                                return;

#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("Received {} bytes via SMB pipe {}", input.size(), m_param2);
#endif

                        if(res && !input.empty())
                        {
                                string output;
                                bool ret = handleMessages(input, output);

#ifdef BUILD_TEAMSERVER
                                if(m_logger && m_logger->should_log(spdlog::level::debug))
                                        m_logger->debug("Sending {} bytes via SMB pipe {}", output.size(), m_param2);
#endif

                                res = m_serverSmb->sendData(output);
                                if(res)
                                {
#ifdef BUILD_TEAMSERVER
                                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                                m_logger->debug("SMB response sent successfully");
#endif
                                }
                        }
        }
    }
    catch (...)
    {
        return;
    }

    return;
}
