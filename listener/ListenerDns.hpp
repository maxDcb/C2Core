#pragma once

#include "Listener.hpp"


namespace dns
{
	class Server;
}

class ListenerDns : public Listener
{

public:
        ListenerDns(const std::string& domainToResolve, int port, const nlohmann::json& config = nlohmann::json::object());
	~ListenerDns();

private:
	void launchDnsListener();

	dns::Server* m_serverDns;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_dnsListener;
};
