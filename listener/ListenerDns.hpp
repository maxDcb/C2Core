#pragma once

#include <server.hpp>
#include <client.hpp>
#include "Listener.hpp"


class ListenerDns : public Listener
{

public:
	ListenerDns(const std::string& domainToResolve, int port);
	~ListenerDns();

private:
	void launchDnsListener();

	dns::Server m_serverDns;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_dnsListener;
};
