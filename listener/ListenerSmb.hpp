#pragma once

#include <PipeHandler.hpp>
#include "Listener.hpp"


class ListenerSmb : public Listener
{

public:
	ListenerSmb(const std::string& ip, const std::string& pipeName);
	~ListenerSmb();

private:
	void lauchSmbServ();

	PipeHandler::Server* m_serverSmb;

	bool m_stopThread;
	std::unique_ptr<std::thread> m_smbServ;
};
