#pragma once

#include "Listener.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"


class ListenerHttp : public Listener
{

public:
        ListenerHttp(const std::string& ip, int localport, const nlohmann::json& config, bool isHttps=false);
        ~ListenerHttp();

    int init();

private:
    void launchHttpServ();

    int HandleCheckIn(const httplib::Request& req, httplib::Response& res);
    int HandleCheckIn(const std::string& requestData, httplib::Response& res);

    std::string m_host;
    int m_port;
        bool m_isHttps;
        nlohmann::json m_listenerConfig;

    std::unique_ptr<httplib::Server> m_svr;
    std::unique_ptr<std::thread> m_httpServ;
};
