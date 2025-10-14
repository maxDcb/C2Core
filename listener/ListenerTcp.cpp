#include "ListenerTcp.hpp"
#include <SocketServer.hpp>

using namespace std;
using json = nlohmann::json;


ListenerTcp::ListenerTcp(const std::string& ip, int localPort, const nlohmann::json& config)
        : Listener("0.0.0.0", std::to_string(localPort), ListenerTcpType)
        , m_stopThread(true)
{
    m_listenerHash = random_string(SizeListenerHash);

    json metadata;
    metadata["1"] = ListenerTcpType;
    metadata["2"] = ip;
    metadata["3"] = std::to_string(localPort);
    m_metadata = metadata.dump();

    m_port = localPort;

    m_serverTcp = new SocketServer(m_port);

#ifdef BUILD_TEAMSERVER
    // Logger
    std::vector<spdlog::sink_ptr> sinks;

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logLevel = resolveLogLevel(config);
        console_sink->set_level(logLevel);
    sinks.push_back(console_sink);


        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+ListenerTcpType+"_"+std::to_string(localPort)+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
        file_sink->set_level(spdlog::level::trace);
    sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+ListenerTcpType+"_"+std::to_string(localPort)+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
        m_logger->set_level(logLevel);
        m_logger->info("Initializing TCP listener on port {}", localPort);
#endif
}


int ListenerTcp::init()
{
    try
    {
        int maxAttempt=10;
        int attempts=0;
        while(!m_serverTcp->isServerLaunched())
        {
            m_serverTcp->stop();
            m_serverTcp->launch();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            // std::cout << "Wait for SocksServer to start on port " << m_port << std::endl;
            attempts++;
            if(attempts>maxAttempt)
            {            
                // std::cout << "Unable to start the SocksServer on port " << m_port << " after " << maxAttempt << " attempts" << std::endl;
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->error("Unable to start the SocksServer on port {}", m_port);
#endif
            }
        }

        if(m_serverTcp->isServerStoped())
        {
            // std::cout << "Start SocksServer failed on port " << m_port << std::endl;
            return -1;
        }

#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->info("TCP listener started on port {}", m_port);
#endif

        m_stopThread=false;
        m_tcpServ = std::make_unique<std::thread>(&ListenerTcp::launchTcpServ, this);
    }
    catch(const std::exception& e)
    {
        // std::cout << e.what() << '\n';
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("TCP listener initialization failure: {}", e.what());
#endif
        return -1;
    }
    
    return 1;
}


ListenerTcp::~ListenerTcp()
{
    if(m_stopThread==false)
    {
        m_stopThread=true;
        m_tcpServ->join();
    }    

    delete m_serverTcp;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("TCP listener stopped on port {}", m_port);
#endif
}


int ListenerTcp::splitInPacket(const std::string& input, std::vector<std::string>& output) 
{
    std::string delimiter = "<TCP-666>";
    size_t pos = 0;
    size_t start = 0;

    while ((pos = input.find(delimiter, start)) != std::string::npos) {
        output.push_back(input.substr(start, pos - start));
        start = pos + delimiter.length();
    }

    if (start < input.length()) 
    {
        output.push_back(input.substr(start));
    }

    return output.size();
}


void ListenerTcp::launchTcpServ()
{
    try 
    {
        while(!m_stopThread)
        {
            for(int i=0; i<m_serverTcp->m_socketTunnelServers.size(); i++)
            {
                if(m_serverTcp->m_socketTunnelServers[i]!=nullptr)
                {
                    std::string input;
                    int res = m_serverTcp->m_socketTunnelServers[i]->recv(input);

                                        if(res<0)
                                        {
                                                m_serverTcp->m_socketTunnelServers[i].reset(nullptr);
#ifdef BUILD_TEAMSERVER
                                                if(m_logger)
                                                        m_logger->warn("Closed TCP tunnel {} due to read failure", i);
#endif
                                        }
                    else if(!input.empty())
                    {
                        std::vector<std::string> trames;
                        splitInPacket(input, trames);

                        for(int j=0; j<trames.size(); j++)
                        {
                            std::string output;
                            handleMessages(trames[j], output);
                            output.append("<TCP-666>");
                            m_serverTcp->m_socketTunnelServers[i]->send(output);
                        }
                    }
                }
            }

            // Remove ended tunnels
            m_serverTcp->cleanTunnel();

            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    catch (...)
    {
        return;
    }

    return;
}

