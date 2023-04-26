#pragma once

#include "Listener.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../thirdParty/cpp-httplib/httplib.h"


class ListenerHttp : public Listener
{

public:
	ListenerHttp(const std::string& ip, int localport, bool isHttps=false);
	~ListenerHttp();

private:
	void lauchHttpServ();

	int HandleCheckIn(const httplib::Request& req, httplib::Response& res);

	bool m_isHttps;

	std::unique_ptr<httplib::Server> m_svr;
	std::unique_ptr<std::thread> m_httpServ;
};
