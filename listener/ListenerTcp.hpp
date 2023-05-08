#pragma once

#include <SocketHandler.hpp>
#include "Listener.hpp"


class ListenerTcp : public Listener
{

public:
	ListenerTcp(const std::string& ip, int localport);
	~ListenerTcp();

private:
	void lauchTcpServ();

	SocketHandler::Server* m_serverTcp;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_tcpServ;
};
