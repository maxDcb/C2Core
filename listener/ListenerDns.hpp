#pragma once

#include "Listener.hpp"
#include <atomic>


namespace dns
{
    class Server;
}

class ListenerDns : public Listener
{

public:
        ListenerDns(const std::string& domainToResolve, int port, const nlohmann::json& config = nlohmann::json::object());
    ~ListenerDns();
    bool isRunning() const { return m_running.load(); }

private:
    void launchDnsListener();

    std::unique_ptr<dns::Server> m_serverDns;

    std::atomic<bool> m_stopThread{false};
    std::atomic<bool> m_running{false};
    std::unique_ptr<std::thread> m_dnsListener;
};
