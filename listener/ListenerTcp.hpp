#pragma once

#include "Listener.hpp"
#include <atomic>


class SocketServer;

class ListenerTcp : public Listener
{

public:
        ListenerTcp(const std::string& ip, int localport, const nlohmann::json& config = nlohmann::json::object());
    ~ListenerTcp();
    
    int init();

private:
    void launchTcpServ();

    SocketServer* m_serverTcp;

    int m_port;

    std::atomic<bool> m_stopThread;
    std::unique_ptr<std::thread> m_tcpServ;
};
