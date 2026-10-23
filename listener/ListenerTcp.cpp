#include "ListenerTcp.hpp"
#include <SocketServer.hpp>
#include "../TcpFrameBuffer.hpp"

#include <unordered_map>

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
        if (m_tcpServ && m_tcpServ->joinable())
            return 1;

        m_serverTcp->launch();
        if (!m_serverTcp->isServerLaunched())
        {
#ifdef BUILD_TEAMSERVER
            if(m_logger)
                m_logger->error("Unable to start TCP listener on port {}", m_port);
#endif
            return -1;
        }

#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->info("TCP listener started on port {}", m_port);
#endif

        m_stopThread.store(false);
        m_tcpServ = std::make_unique<std::thread>(&ListenerTcp::launchTcpServ, this);
    }
    catch(const std::exception& e)
    {
        // std::cout << e.what() << '\n';
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("TCP listener initialization failure: {}", e.what());
#endif
        m_serverTcp->stop();
        return -1;
    }
    
    return 1;
}


ListenerTcp::~ListenerTcp()
{
    m_stopThread.store(true);
    m_serverTcp->stop();
    if(m_tcpServ && m_tcpServ->joinable())
        m_tcpServ->join();

    delete m_serverTcp;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("TCP listener stopped on port {}", m_port);
#endif
}


void ListenerTcp::launchTcpServ()
{
    std::unordered_map<SocketTunnelServer*, TcpFrameBuffer> frameBuffers;
    try 
    {
        while(!m_stopThread.load())
        {
            const auto tunnels = m_serverTcp->getTunnels();
            for(const auto& tunnel : tunnels)
            {
                if(!tunnel)
                    continue;
                if(tunnel->isClosed())
                {
                    frameBuffers.erase(tunnel.get());
                    continue;
                }
                try
                {
                    std::string input;
                    int res = tunnel->recv(input);

                    if(res <= 0)
                    {
                        tunnel->close();
                        frameBuffers.erase(tunnel.get());
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                            m_logger->warn("Closed TCP tunnel due to read failure");
#endif
                    }
                    else if(!input.empty())
                    {
                        std::vector<std::string> frames;
                        if (!frameBuffers[tunnel.get()].append(input, frames))
                        {
                            tunnel->close();
                            frameBuffers.erase(tunnel.get());
                            continue;
                        }

                        for(const auto& frame : frames)
                        {
                            std::string output;
                            handleMessages(frame, output);
                            output.append(TcpFrameBuffer::delimiter());
                            if (tunnel->send(output) < 0)
                            {
                                frameBuffers.erase(tunnel.get());
                                break;
                            }
                        }
                    }
                }
                catch (...)
                {
                    tunnel->close();
                    frameBuffers.erase(tunnel.get());
                }
            }

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

