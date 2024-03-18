#pragma once

#include "Listener.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../thirdParty/cpp-httplib/httplib.h"


class ListenerHttp : public Listener
{

public:
	ListenerHttp(const std::string& ip, int localport, const nlohmann::json& config, bool isHttps=false);
	~ListenerHttp();

private:
	void lauchHttpServ();

	int HandleCheckIn(const httplib::Request& req, httplib::Response& res);

	std::string m_host;
	int m_port;
	bool m_isHttps;
	nlohmann::json m_config;

	std::unique_ptr<httplib::Server> m_svr;
	std::unique_ptr<std::thread> m_httpServ;
};
