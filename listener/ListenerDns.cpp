#include "ListenerDns.hpp"
#include <server.hpp>
#include <client.hpp>


using namespace std;
using json = nlohmann::json;


ListenerDns::ListenerDns(const std::string& domainToResolve, int port, const nlohmann::json& config)
        : Listener(domainToResolve, std::to_string(port), ListenerDnsType)
{
        m_serverDns = std::make_unique<dns::Server>(port, domainToResolve);

        m_listenerHash = random_string(SizeListenerHash);

    json metadata;
    metadata["1"] = ListenerDnsType;
    metadata["2"] = domainToResolve;
    metadata["3"] = std::to_string(port);
    m_metadata = metadata.dump();

#ifdef BUILD_TEAMSERVER
        // Logger
        std::vector<spdlog::sink_ptr> sinks;

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logLevel = resolveLogLevel(config);
        console_sink->set_level(logLevel);
    sinks.push_back(console_sink);


        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+ListenerDnsType+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
        file_sink->set_level(spdlog::level::trace);
        sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+ListenerDnsType+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
        m_logger->set_level(logLevel);
        m_logger->info("Initializing DNS listener for {} on port {}", domainToResolve, port);
#endif

        if (!m_serverDns->launch())
                return;

        m_running.store(true);

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("DNS listener started for {} on port {}", domainToResolve, port);
#endif

        m_stopThread.store(false);
        m_dnsListener = std::make_unique<std::thread>(&ListenerDns::launchDnsListener, this);
}


ListenerDns::~ListenerDns()
{
        m_stopThread.store(true);
        if (m_serverDns)
                m_serverDns->stop();

        if (m_dnsListener && m_dnsListener->joinable())
                m_dnsListener->join();
        m_running.store(false);

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("DNS listener stopped for {}", m_param1);
#endif
}


void ListenerDns::launchDnsListener()
{
    while(!m_stopThread.load())
    {
        try
        {
            auto [clientId, input] = m_serverDns->getAvailableMessage();

#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("Received {} bytes from DNS client {}", input.size(), clientId);
#endif

                        if(!input.empty())
                        {
                                string output;
                                std::vector<PendingTask> dequeuedTasks;
                                try
                                {
                                        handleMessages(input, output, &dequeuedTasks);

#ifdef BUILD_TEAMSERVER
                                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                                m_logger->debug("Sending {} bytes to DNS client {}", output.size(), clientId);
#endif

                                        if((output.empty() && !dequeuedTasks.empty()) ||
                                           (!output.empty() &&
                                            !m_serverDns->setMessageToSend(output, clientId)))
                                                restoreTasks(dequeuedTasks);
                                }
                                catch (...)
                                {
                                        restoreTasks(dequeuedTasks);
                                }
                        }
        }
        catch (...)
        {
            // A malformed exchange must not terminate the listener worker.
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    m_running.store(false);
}

