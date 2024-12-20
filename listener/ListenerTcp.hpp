#pragma once

#include <SocketServer.hpp>
#include "Listener.hpp"


class ListenerTcp : public Listener
{

public:
	ListenerTcp(const std::string& ip, int localport);
	~ListenerTcp();
	
	int init();

private:
	void lauchTcpServ();
	int splitInPacket(const std::string& input, std::vector<std::string>& output);

	SocketServer* m_serverTcp;

	int m_port;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_tcpServ;
};
