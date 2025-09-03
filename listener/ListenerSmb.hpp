#pragma once

#include "Listener.hpp"


namespace PipeHandler
{
	class Server;
}

class ListenerSmb : public Listener
{

public:
	ListenerSmb(const std::string& ip, const std::string& pipeName);
	~ListenerSmb();

private:
	void launchSmbServ();

	PipeHandler::Server* m_serverSmb;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_smbServ;
};
